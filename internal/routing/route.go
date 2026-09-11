package routing

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var (
	cachedGateway  string
	cachedIface    string
	cacheTime      time.Time
	cacheTTL       = 60 * time.Second
	gatewayCacheMu sync.Mutex
)

const maxCleanupAttempts = 32

func safeDeleteLoop(desc string, cmd string, args ...string) {
	for i := 0; i < maxCleanupAttempts; i++ {
		if err := runCmd(cmd, args...); err != nil {
			return
		}
	}
	log.Printf("[Routing] Warning: cleanup loop reached max attempts (%d) for %s: %s %v", maxCleanupAttempts, desc, cmd, args)
}

// SetupSlotRouting configures policy routing for a specific slot and interface
func SetupSlotRouting(slotIndex int, interfaceName string) error {
	ident := SlotRoutingIdentity(slotIndex)

	// 1. Add IP rule based on fwmark (flush stale duplicate rules first for idempotency)
	safeDeleteLoop(fmt.Sprintf("Slot %d ip rule", slotIndex), "ip", "rule", "del", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID))
	if err := runCmd("ip", "rule", "add", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID), "pref", fmt.Sprintf("%d", ident.Priority)); err != nil {
		log.Printf("[Slot %d] Note: ip rule add returned (might already exist): %v", slotIndex, err)
	}

	// 2. Clear old routes in the table
	runCmd("ip", "route", "flush", "table", fmt.Sprintf("%d", ident.TableID))

	// 3. Add default route to the table pointing to the tun interface
	if err := runCmd("ip", "route", "add", "default", "dev", interfaceName, "table", fmt.Sprintf("%d", ident.TableID)); err != nil {
		return fmt.Errorf("failed to add default route for %s: %w", interfaceName, err)
	}

	// 4. IPv6 Leak Protection (P1-13)
	safeDeleteLoop(fmt.Sprintf("Slot %d ip -6 rule", slotIndex), "ip", "-6", "rule", "del", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID))
	if err := runCmd("ip", "-6", "rule", "add", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID), "pref", fmt.Sprintf("%d", ident.Priority)); err != nil {
		log.Printf("[Slot %d] Note: ip -6 rule add returned: %v", slotIndex, err)
	}
	runCmd("ip", "-6", "route", "add", "blackhole", "default", "table", fmt.Sprintf("%d", ident.TableID))

	// 5. CONNMARK rules for connection tracking (required for DRAINING)
	if err := SetupConnmarkRules(slotIndex); err != nil {
		log.Printf("[Slot %d] Warning: failed to setup CONNMARK rules: %v", slotIndex, err)
	}

	log.Printf("[Slot %d] Routing setup complete: fwmark %d -> table %d -> dev %s", slotIndex, ident.Mark, ident.TableID, interfaceName)
	return nil
}

// ClearSlotRouting resets the policy routing for a slot to fail-closed unreachable state.
// This prevents traffic with this slot's fwmark from leaking out to the physical WAN interface.
func ClearSlotRouting(slotIndex int) error {
	ident := SlotRoutingIdentity(slotIndex)

	// Clean up CONNMARK rules first
	ClearConnmarkRules(slotIndex)

	// Flush old routes in slot table
	_ = runCmd("ip", "route", "flush", "table", fmt.Sprintf("%d", ident.TableID))
	_ = runCmd("ip", "-6", "route", "flush", "table", fmt.Sprintf("%d", ident.TableID))

	// Fail-closed: insert unreachable / blackhole default route
	_ = runCmd("ip", "route", "add", "unreachable", "default", "table", fmt.Sprintf("%d", ident.TableID))
	_ = runCmd("ip", "-6", "route", "add", "blackhole", "default", "table", fmt.Sprintf("%d", ident.TableID))

	// Ensure fwmark rule stays pointed to this table so marked packets hit unreachable
	safeDeleteLoop(fmt.Sprintf("Slot %d clear ip rule", slotIndex), "ip", "rule", "del", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID))
	_ = runCmd("ip", "rule", "add", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID), "pref", fmt.Sprintf("%d", ident.Priority))

	safeDeleteLoop(fmt.Sprintf("Slot %d clear ip -6 rule", slotIndex), "ip", "-6", "rule", "del", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID))
	_ = runCmd("ip", "-6", "rule", "add", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID), "pref", fmt.Sprintf("%d", ident.Priority))

	log.Printf("[Slot %d] Routing cleared to fail-closed unreachable state (table %d).", slotIndex, ident.TableID)
	return nil
}

// TeardownSlotRouting completely removes rules and routes for a slot (used on graceful daemon shutdown).
func TeardownSlotRouting(slotIndex int) {
	ident := SlotRoutingIdentity(slotIndex)

	ClearConnmarkRules(slotIndex)
	_ = runCmd("ip", "route", "flush", "table", fmt.Sprintf("%d", ident.TableID))
	_ = runCmd("ip", "-6", "route", "flush", "table", fmt.Sprintf("%d", ident.TableID))

	safeDeleteLoop(fmt.Sprintf("Slot %d teardown ip rule", slotIndex), "ip", "rule", "del", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID))
	safeDeleteLoop(fmt.Sprintf("Slot %d teardown ip -6 rule", slotIndex), "ip", "-6", "rule", "del", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID))
	log.Printf("[Slot %d] Policy routing torn down cleanly.", slotIndex)
}

// SetupCandidateRouting establishes an isolated policy route and fwmark for candidate
// tunnel qualification without altering the active slot's routing or traffic.
func SetupCandidateRouting(candidateSlot int, interfaceName string) error {
	ident := SlotRoutingIdentity(candidateSlot)

	safeDeleteLoop(fmt.Sprintf("Candidate %d ip rule", candidateSlot), "ip", "rule", "del", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID))
	if err := runCmd("ip", "rule", "add", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID), "pref", fmt.Sprintf("%d", ident.Priority)); err != nil {
		log.Printf("[Candidate %d] Note: ip rule add returned: %v", candidateSlot, err)
	}

	_ = runCmd("ip", "route", "flush", "table", fmt.Sprintf("%d", ident.TableID))
	if err := runCmd("ip", "route", "add", "default", "dev", interfaceName, "table", fmt.Sprintf("%d", ident.TableID)); err != nil {
		return fmt.Errorf("failed to add default route for candidate %s: %w", interfaceName, err)
	}

	safeDeleteLoop(fmt.Sprintf("Candidate %d ip -6 rule", candidateSlot), "ip", "-6", "rule", "del", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID))
	_ = runCmd("ip", "-6", "rule", "add", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID), "pref", fmt.Sprintf("%d", ident.Priority))
	_ = runCmd("ip", "-6", "route", "add", "blackhole", "default", "table", fmt.Sprintf("%d", ident.TableID))

	log.Printf("[Candidate %d] Candidate routing established: fwmark %d -> table %d -> dev %s", candidateSlot, ident.Mark, ident.TableID, interfaceName)
	return nil
}

// ClearCandidateRouting removes candidate policy routing and flushes the temporary table.
func ClearCandidateRouting(candidateSlot int) {
	ident := SlotRoutingIdentity(candidateSlot)

	_ = runCmd("ip", "route", "flush", "table", fmt.Sprintf("%d", ident.TableID))
	_ = runCmd("ip", "-6", "route", "flush", "table", fmt.Sprintf("%d", ident.TableID))
	safeDeleteLoop(fmt.Sprintf("Candidate %d clear ip rule", candidateSlot), "ip", "rule", "del", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID))
	safeDeleteLoop(fmt.Sprintf("Candidate %d clear ip -6 rule", candidateSlot), "ip", "-6", "rule", "del", "fwmark", fmt.Sprintf("%d", ident.Mark), "table", fmt.Sprintf("%d", ident.TableID))
	log.Printf("[Candidate %d] Candidate routing cleared.", candidateSlot)
}

// GetDefaultGateway finds the default gateway and physical interface of the main table.
// Results are cached with a TTL to handle network changes (DHCP renewal, failover).
func GetDefaultGateway() (string, string, error) {
	gatewayCacheMu.Lock()
	defer gatewayCacheMu.Unlock()

	if cachedGateway != "" && cachedIface != "" && time.Since(cacheTime) < cacheTTL {
		return cachedGateway, cachedIface, nil
	}

	cmd := exec.Command("ip", "route", "show", "default")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("failed to get default route: %v", err)
	}

	// Example output: default via 172.17.0.1 dev eth0 proto static
	fields := strings.Fields(string(output))
	var gw, iface string
	for i, f := range fields {
		if f == "via" && i+1 < len(fields) {
			gw = fields[i+1]
		}
		if f == "dev" && i+1 < len(fields) {
			iface = fields[i+1]
		}
	}

	if gw == "" || iface == "" {
		return "", "", fmt.Errorf("could not parse default route: %s", string(output))
	}

	cachedGateway = gw
	cachedIface = iface
	cacheTime = time.Now()
	return gw, iface, nil
}

// AddEndpointBypassRule forces underlay traffic to the VPN endpoint to go through the physical NIC
// using centralized reference counting to prevent prematurely deleting routes shared by multiple tunnels.
func AddEndpointBypassRule(serverIP string) error {
	return GetEndpointManager().AcquireEndpoint(serverIP)
}

// RemoveEndpointBypassRule decrements the reference count and removes the underlay bypass
// route when no more tunnels rely on this endpoint.
func RemoveEndpointBypassRule(serverIP string) error {
	return GetEndpointManager().ReleaseEndpoint(serverIP)
}

func runCmd(name string, args ...string) error {
	/* #nosec G204 */
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v failed: %w, output: %s", name, args, err, string(output))
	}
	return nil
}

// GetInterfaceIP returns the primary IPv4 address configured on an interface
func GetInterfaceIP(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("failed to get interface %s: %w", ifaceName, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("failed to get addresses for %s: %w", ifaceName, err)
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip != nil && ip.To4() != nil && !ip.IsLoopback() {
			return ip.String(), nil
		}
	}
	return "", fmt.Errorf("no IPv4 address found on interface %s", ifaceName)
}

// SetupDrainingRouting isolates a draining tunnel into its dedicated table (BaseDrainingTable + slot)
// and pins all existing flows with source IP = tunIP to exit through this draining table.
// New connections from Xray will NOT match tunIP and will route via the active slot table.
func SetupDrainingRouting(drainingTableID int, interfaceName string, tunIP string) error {
	// 1. Flush old routes in draining table
	runCmd("ip", "route", "flush", "table", fmt.Sprintf("%d", drainingTableID))

	// 2. Add default route dev interface in draining table
	if err := runCmd("ip", "route", "add", "default", "dev", interfaceName, "table", fmt.Sprintf("%d", drainingTableID)); err != nil {
		return fmt.Errorf("failed to add default route to draining table %d for %s: %w", drainingTableID, interfaceName, err)
	}

	// 3. Pin existing connections bound to tunIP to this draining table
	if tunIP != "" {
		if err := runCmd("ip", "rule", "add", "from", tunIP, "table", fmt.Sprintf("%d", drainingTableID), "pref", "50"); err != nil {
			log.Printf("[Draining] Note: ip rule add from %s returned: %v", tunIP, err)
		}
	}

	// 4. Blackhole IPv6 on draining table
	runCmd("ip", "-6", "route", "add", "blackhole", "default", "table", fmt.Sprintf("%d", drainingTableID))

	log.Printf("[Draining] Routing setup for draining table %d (dev %s, tunIP %s)", drainingTableID, interfaceName, tunIP)
	return nil
}

// ClearDrainingRouting tears down the dedicated draining table and rules
func ClearDrainingRouting(drainingTableID int, tunIP string) {
	if tunIP != "" {
		runCmd("ip", "rule", "del", "from", tunIP, "table", fmt.Sprintf("%d", drainingTableID), "pref", "50")
	}
	runCmd("ip", "route", "flush", "table", fmt.Sprintf("%d", drainingTableID))
	log.Printf("[Draining] Cleared draining routing table %d", drainingTableID)
}

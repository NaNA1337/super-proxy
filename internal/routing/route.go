package routing

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const BaseTableID = 100

var (
	cachedGateway  string
	cachedIface    string
	cacheTime      time.Time
	cacheTTL       = 60 * time.Second
	gatewayCacheMu sync.Mutex
)

// SetupSlotRouting configures policy routing for a specific slot and interface
func SetupSlotRouting(slotIndex int, interfaceName string) error {
	tableID := BaseTableID + slotIndex
	fwmark := tableID // use the same number for simplicity

	// 1. Add IP rule based on fwmark
	if err := runCmd("ip", "rule", "add", "fwmark", fmt.Sprintf("%d", fwmark), "table", fmt.Sprintf("%d", tableID)); err != nil {
		log.Printf("[Slot %d] Note: ip rule add returned (might already exist): %v", slotIndex, err)
	}

	// 2. Clear old routes in the table
	runCmd("ip", "route", "flush", "table", fmt.Sprintf("%d", tableID))

	// 3. Add default route to the table pointing to the tun interface
	if err := runCmd("ip", "route", "add", "default", "dev", interfaceName, "table", fmt.Sprintf("%d", tableID)); err != nil {
		return fmt.Errorf("failed to add default route for %s: %w", interfaceName, err)
	}

	// 4. IPv6 Leak Protection (P1-13)
	if err := runCmd("ip", "-6", "rule", "add", "fwmark", fmt.Sprintf("%d", fwmark), "table", fmt.Sprintf("%d", tableID)); err != nil {
		log.Printf("[Slot %d] Note: ip -6 rule add returned: %v", slotIndex, err)
	}
	runCmd("ip", "-6", "route", "add", "blackhole", "default", "table", fmt.Sprintf("%d", tableID))

	// 5. CONNMARK rules for connection tracking (required for DRAINING)
	if err := SetupConnmarkRules(slotIndex); err != nil {
		log.Printf("[Slot %d] Warning: failed to setup CONNMARK rules: %v", slotIndex, err)
	}

	log.Printf("[Slot %d] Routing setup complete: fwmark %d -> table %d -> dev %s", slotIndex, fwmark, tableID, interfaceName)
	return nil
}

// ClearSlotRouting removes the policy routing for a specific slot
func ClearSlotRouting(slotIndex int) error {
	tableID := BaseTableID + slotIndex
	fwmark := tableID

	// Clean up CONNMARK rules first
	ClearConnmarkRules(slotIndex)

	if err := runCmd("ip", "route", "flush", "table", fmt.Sprintf("%d", tableID)); err != nil {
		log.Printf("[Slot %d] Note: failed to flush route table: %v", slotIndex, err)
	}

	if err := runCmd("ip", "rule", "del", "fwmark", fmt.Sprintf("%d", fwmark), "table", fmt.Sprintf("%d", tableID)); err != nil {
		log.Printf("[Slot %d] Note: ip rule del returned: %v", slotIndex, err)
	}

	// Clean up IPv6 rule (P1-13)
	if err := runCmd("ip", "-6", "rule", "del", "fwmark", fmt.Sprintf("%d", fwmark), "table", fmt.Sprintf("%d", tableID)); err != nil {
		log.Printf("[Slot %d] Note: ip -6 rule del returned: %v", slotIndex, err)
	}

	log.Printf("[Slot %d] Routing cleared.", slotIndex)
	return nil
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
func AddEndpointBypassRule(serverIP string) error {
	gw, iface, err := GetDefaultGateway()
	if err != nil {
		log.Printf("[Routing] Failed to determine default gateway, falling back to ip rule: %v", err)
		// Fallback to old behavior if we can't find the gateway
		return runCmd("ip", "rule", "add", "to", serverIP, "lookup", "main", "pref", "10")
	}

	// P0-5 & Requirement 7: Explicit /32 host route to physical NIC
	err = runCmd("ip", "route", "add", fmt.Sprintf("%s/32", serverIP), "via", gw, "dev", iface)
	if err != nil {
		// If route exists, that's fine, but log it
		log.Printf("[Routing] Note: failed to add /32 endpoint route for %s: %v", serverIP, err)
		return err
	}
	log.Printf("[Routing] Explicit /32 endpoint route added for %s via %s dev %s", serverIP, gw, iface)
	return nil
}

// RemoveEndpointBypassRule cleans up the underlay bypass rule
func RemoveEndpointBypassRule(serverIP string) error {
	gw, iface, err := GetDefaultGateway()
	if err != nil {
		return runCmd("ip", "rule", "del", "to", serverIP, "lookup", "main", "pref", "10")
	}

	err = runCmd("ip", "route", "del", fmt.Sprintf("%s/32", serverIP), "via", gw, "dev", iface)
	if err != nil {
		log.Printf("[Routing] Note: failed to remove /32 endpoint route for %s: %v", serverIP, err)
		return err
	}
	log.Printf("[Routing] Explicit /32 endpoint route removed for %s", serverIP)
	return nil
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

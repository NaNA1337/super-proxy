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

// EndpointManager manages underlay bypass host routes with thread-safe reference counting.
// This guarantees that when multiple tunnels share the same endpoint IP, tearing down one
// tunnel does not remove the route required by other active tunnels.
type EndpointManager struct {
	mu        sync.Mutex
	refCounts map[string]int
}

var (
	globalEndpointMgr     *EndpointManager
	endpointMgrOnce       sync.Once
	cachedIPv6GW          string
	cachedIPv6Iface       string
	cacheIPv6Time         time.Time
	cacheIPv6TTL          = 60 * time.Second
	ipv6GatewayCacheMu    sync.Mutex
)

// GetEndpointManager returns the singleton EndpointManager instance
func GetEndpointManager() *EndpointManager {
	endpointMgrOnce.Do(func() {
		globalEndpointMgr = &EndpointManager{
			refCounts: make(map[string]int),
		}
	})
	return globalEndpointMgr
}

// GetDefaultIPv6Gateway finds the default IPv6 gateway and interface
func GetDefaultIPv6Gateway() (string, string, error) {
	ipv6GatewayCacheMu.Lock()
	defer ipv6GatewayCacheMu.Unlock()

	if cachedIPv6GW != "" && cachedIPv6Iface != "" && time.Since(cacheIPv6Time) < cacheIPv6TTL {
		return cachedIPv6GW, cachedIPv6Iface, nil
	}

	cmd := exec.Command("ip", "-6", "route", "show", "default")
	output, err := cmd.CombinedOutput()
	if err != nil || len(output) == 0 {
		return "", "", fmt.Errorf("no default IPv6 route found: %v", err)
	}

	// Example: default via fe80::1 dev eth0 proto ra metric 1024
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
		return "", "", fmt.Errorf("could not parse IPv6 default route: %s", string(output))
	}

	cachedIPv6GW = gw
	cachedIPv6Iface = iface
	cacheIPv6Time = time.Now()
	return gw, iface, nil
}

// EnsureEndpointBypassRoute guarantees that the host route for serverIP exits through the
// physical interface and default gateway, preventing routing recursion into tun interfaces.
// It implements idempotent semantics:
// - already exists and correct -> success
// - does not exist -> add
// - exists but wrong (e.g. points to tunX) -> replace/fix
// - cannot confirm -> fail closed
func EnsureEndpointBypassRoute(serverIP string) error {
	if serverIP == "" {
		return fmt.Errorf("serverIP cannot be empty")
	}

	parsedIP := net.ParseIP(serverIP)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", serverIP)
	}

	isIPv4 := parsedIP.To4() != nil

	if isIPv4 {
		gw, iface, err := GetDefaultGateway()
		if err != nil {
			return fmt.Errorf("failed to get IPv4 default gateway for endpoint bypass: %w", err)
		}

		cidr := fmt.Sprintf("%s/32", serverIP)

		// 1. Inspect existing exact route
		showCmd := exec.Command("ip", "route", "show", "exact", cidr)
		showOut, _ := showCmd.CombinedOutput()
		showStr := string(showOut)

		needsInstall := false
		if len(strings.TrimSpace(showStr)) == 0 {
			needsInstall = true
		} else if strings.Contains(showStr, "tun") || !strings.Contains(showStr, iface) {
			log.Printf("[EndpointManager] Existing route for %s is misdirected (%s), replacing with physical %s via %s",
				cidr, strings.TrimSpace(showStr), iface, gw)
			if err := runCmd("ip", "route", "replace", cidr, "via", gw, "dev", iface); err != nil {
				return fmt.Errorf("failed to replace misdirected route %s: %w", cidr, err)
			}
		} else {
			log.Printf("[EndpointManager] Verified existing route for %s is correctly directed to %s", cidr, iface)
		}

		if needsInstall {
			if err := runCmd("ip", "route", "add", cidr, "via", gw, "dev", iface); err != nil {
				if strings.Contains(err.Error(), "File exists") {
					// Fallback to replace in case of concurrent add
					if rErr := runCmd("ip", "route", "replace", cidr, "via", gw, "dev", iface); rErr != nil {
						return fmt.Errorf("failed to replace route %s on conflict: %w", cidr, rErr)
					}
				} else {
					return fmt.Errorf("failed to add /32 endpoint bypass route for %s: %w", serverIP, err)
				}
			}
		}

		// 2. Read-back verification (fail closed if not routing via physical interface)
		getCmd := exec.Command("ip", "route", "get", serverIP)
		getOut, getErr := getCmd.CombinedOutput()
		if getErr != nil {
			return fmt.Errorf("route read-back verification failed for %s: %w", serverIP, getErr)
		}
		getStr := string(getOut)
		if strings.Contains(getStr, "dev tun") || !strings.Contains(getStr, iface) {
			return fmt.Errorf("FATAL: endpoint route for %s does not resolve to physical interface %s (resolved: %s)", serverIP, iface, getStr)
		}

		log.Printf("[EndpointManager] Ensured IPv4 /32 bypass route for %s via %s dev %s", serverIP, gw, iface)
		return nil
	}

	// IPv6 Host Route /128
	gw6, iface6, err := GetDefaultIPv6Gateway()
	if err != nil {
		return fmt.Errorf("FATAL: IPv6 underlay gateway not available on physical interface; refusing to route endpoint %s to avoid leak/recursion: %w", serverIP, err)
	}

	cidr6 := fmt.Sprintf("%s/128", serverIP)
	showCmd := exec.Command("ip", "-6", "route", "show", "exact", cidr6)
	showOut, _ := showCmd.CombinedOutput()
	showStr := string(showOut)

	needsInstall6 := false
	if len(strings.TrimSpace(showStr)) == 0 {
		needsInstall6 = true
	} else if strings.Contains(showStr, "tun") || !strings.Contains(showStr, iface6) {
		log.Printf("[EndpointManager] Existing IPv6 route for %s is misdirected (%s), replacing with physical %s via %s",
			cidr6, strings.TrimSpace(showStr), iface6, gw6)
		if err := runCmd("ip", "-6", "route", "replace", cidr6, "via", gw6, "dev", iface6); err != nil {
			return fmt.Errorf("failed to replace misdirected IPv6 route %s: %w", cidr6, err)
		}
	} else {
		log.Printf("[EndpointManager] Verified existing IPv6 route for %s is correctly directed to %s", cidr6, iface6)
	}

	if needsInstall6 {
		if err := runCmd("ip", "-6", "route", "add", cidr6, "via", gw6, "dev", iface6); err != nil {
			if strings.Contains(err.Error(), "File exists") {
				if rErr := runCmd("ip", "-6", "route", "replace", cidr6, "via", gw6, "dev", iface6); rErr != nil {
					return fmt.Errorf("failed to replace IPv6 route %s on conflict: %w", cidr6, rErr)
				}
			} else {
				return fmt.Errorf("failed to add /128 endpoint bypass route for %s: %w", serverIP, err)
			}
		}
	}

	// Read-back verification
	getCmd6 := exec.Command("ip", "-6", "route", "get", serverIP)
	getOut6, getErr6 := getCmd6.CombinedOutput()
	if getErr6 == nil {
		getStr6 := string(getOut6)
		if strings.Contains(getStr6, "dev tun") {
			return fmt.Errorf("FATAL: IPv6 endpoint route for %s resolved into tun device (resolved: %s)", serverIP, getStr6)
		}
	}

	log.Printf("[EndpointManager] Ensured IPv6 /128 bypass route for %s via %s dev %s", serverIP, gw6, iface6)
	return nil
}

// AcquireEndpoint adds an explicit underlay route if not already present,
// and increments the reference count.
func (m *EndpointManager) AcquireEndpoint(serverIP string) error {
	if serverIP == "" {
		return fmt.Errorf("serverIP cannot be empty")
	}

	parsedIP := net.ParseIP(serverIP)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", serverIP)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	currentCount := m.refCounts[serverIP]
	if currentCount > 0 {
		m.refCounts[serverIP]++
		log.Printf("[EndpointManager] Reused existing bypass route for %s (refcount=%d)", serverIP, m.refCounts[serverIP])
		return nil
	}

	if err := EnsureEndpointBypassRoute(serverIP); err != nil {
		return err
	}

	m.refCounts[serverIP] = 1
	return nil
}

// ReleaseEndpoint decrements the reference count and removes the host route
// when the reference count drops to zero.
func (m *EndpointManager) ReleaseEndpoint(serverIP string) error {
	if serverIP == "" {
		return nil
	}

	parsedIP := net.ParseIP(serverIP)
	if parsedIP == nil {
		return fmt.Errorf("invalid IP address: %s", serverIP)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	currentCount, exists := m.refCounts[serverIP]
	if !exists || currentCount <= 0 {
		log.Printf("[EndpointManager] Warning: ReleaseEndpoint called for %s with refcount <= 0", serverIP)
		delete(m.refCounts, serverIP)
		return nil
	}

	m.refCounts[serverIP]--
	if m.refCounts[serverIP] > 0 {
		log.Printf("[EndpointManager] Decremented refcount for %s (remaining=%d)", serverIP, m.refCounts[serverIP])
		return nil
	}

	// Reference count reached 0: delete route
	delete(m.refCounts, serverIP)

	isIPv4 := parsedIP.To4() != nil
	if isIPv4 {
		gw, iface, err := GetDefaultGateway()
		if err != nil {
			log.Printf("[EndpointManager] Warning: failed to get gateway for route deletion: %v", err)
			// Try deleting without gateway
			return runCmd("ip", "route", "del", fmt.Sprintf("%s/32", serverIP))
		}
		if err := runCmd("ip", "route", "del", fmt.Sprintf("%s/32", serverIP), "via", gw, "dev", iface); err != nil {
			log.Printf("[EndpointManager] Note: ip route del returned: %v", err)
		}
		log.Printf("[EndpointManager] Removed IPv4 /32 bypass route for %s (refcount=0)", serverIP)
	} else {
		gw6, iface6, err := GetDefaultIPv6Gateway()
		if err != nil {
			return runCmd("ip", "-6", "route", "del", fmt.Sprintf("%s/128", serverIP))
		}
		if err := runCmd("ip", "-6", "route", "del", fmt.Sprintf("%s/128", serverIP), "via", gw6, "dev", iface6); err != nil {
			log.Printf("[EndpointManager] Note: ip -6 route del returned: %v", err)
		}
		log.Printf("[EndpointManager] Removed IPv6 /128 bypass route for %s (refcount=0)", serverIP)
	}

	return nil
}

// GetRefCount returns current reference count for an endpoint IP (for diagnostics and testing)
func (m *EndpointManager) GetRefCount(serverIP string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.refCounts[serverIP]
}

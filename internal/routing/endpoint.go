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

	isIPv4 := parsedIP.To4() != nil

	currentCount := m.refCounts[serverIP]
	if currentCount > 0 {
		m.refCounts[serverIP]++
		log.Printf("[EndpointManager] Reused existing bypass route for %s (refcount=%d)", serverIP, m.refCounts[serverIP])
		return nil
	}

	// First reference: install the host route
	if isIPv4 {
		gw, iface, err := GetDefaultGateway()
		if err != nil {
			return fmt.Errorf("failed to get IPv4 default gateway for endpoint bypass: %w", err)
		}

		cidr := fmt.Sprintf("%s/32", serverIP)
		if err := runCmd("ip", "route", "add", cidr, "via", gw, "dev", iface); err != nil {
			// If route already exists in kernel table, verify it's reachable or treat as adopted
			if strings.Contains(err.Error(), "File exists") {
				log.Printf("[EndpointManager] Route %s already present in kernel, adopting", cidr)
			} else {
				return fmt.Errorf("failed to add /32 endpoint bypass route: %w", err)
			}
		}
		log.Printf("[EndpointManager] Created IPv4 /32 bypass route for %s via %s dev %s", serverIP, gw, iface)
	} else {
		// IPv6 Host Route /128
		gw6, iface6, err := GetDefaultIPv6Gateway()
		if err != nil {
			// Fail-safe: refusing to silently route IPv6 endpoint via tun/recursion
			return fmt.Errorf("FATAL: IPv6 underlay gateway not available on physical interface; refusing to route endpoint %s to avoid leak/recursion: %w", serverIP, err)
		}

		cidr := fmt.Sprintf("%s/128", serverIP)
		if err := runCmd("ip", "-6", "route", "add", cidr, "via", gw6, "dev", iface6); err != nil {
			if strings.Contains(err.Error(), "File exists") {
				log.Printf("[EndpointManager] Route %s already present in kernel, adopting", cidr)
			} else {
				return fmt.Errorf("failed to add /128 endpoint bypass route: %w", err)
			}
		}
		log.Printf("[EndpointManager] Created IPv6 /128 bypass route for %s via %s dev %s", serverIP, gw6, iface6)
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

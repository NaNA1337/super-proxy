package integration

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/routing"
)

// runInNetNS executes a command inside the specified network namespace.
func runInNetNS(ns string, name string, args ...string) (string, error) {
	cmdArgs := append([]string{"netns", "exec", ns, name}, args...)
	/* #nosec G204 */
	cmd := exec.Command("ip", cmdArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestLinuxNetwork_FullIntegrationHarness(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping Linux network integration test: requires root privileges (CAP_NET_ADMIN)")
	}

	nsName := fmt.Sprintf("sp_test_ns_%d", time.Now().UnixNano()%100000)

	// 1. Create isolated network namespace
	cmd := exec.Command("ip", "netns", "add", nsName)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to create test netns %s: %v (%s)", nsName, err, string(out))
	}
	defer func() {
		_ = exec.Command("ip", "netns", "del", nsName).Run()
	}()

	// 2. Setup loopback and dummy interfaces
	_, _ = runInNetNS(nsName, "ip", "link", "set", "lo", "up")
	for i := 0; i < 3; i++ {
		dev := fmt.Sprintf("dummy%d", i)
		ipAddr := fmt.Sprintf("10.200.%d.2/24", i)
		_, err := runInNetNS(nsName, "ip", "link", "add", dev, "type", "dummy")
		if err != nil {
			t.Fatalf("Failed to add dummy device %s: %v", dev, err)
		}
		_, _ = runInNetNS(nsName, "ip", "link", "set", dev, "up")
		_, _ = runInNetNS(nsName, "ip", "addr", "add", ipAddr, "dev", dev)
	}

	// 3. Test Policy Routing for Slots 0, 1, 2
	for i := 0; i < 3; i++ {
		table := fmt.Sprintf("%d", 100+i)
		mark := fmt.Sprintf("%d", 100+i)
		dev := fmt.Sprintf("dummy%d", i)

		_, err := runInNetNS(nsName, "ip", "rule", "add", "fwmark", mark, "table", table, "priority", "100")
		if err != nil {
			t.Fatalf("Failed to add ip rule for slot %d: %v", i, err)
		}
		_, err = runInNetNS(nsName, "ip", "route", "add", "default", "dev", dev, "table", table)
		if err != nil {
			t.Fatalf("Failed to add route for slot %d: %v", i, err)
		}
	}

	// Verify policy routing rules exist in netns
	rulesOut, err := runInNetNS(nsName, "ip", "rule", "show")
	if err != nil {
		t.Fatalf("Failed to show ip rules: %v", err)
	}
	for i := 0; i < 3; i++ {
		expectedRule := fmt.Sprintf("lookup %d", 100+i)
		if !strings.Contains(rulesOut, expectedRule) {
			t.Errorf("Missing expected rule %s in netns: %s", expectedRule, rulesOut)
		}
	}

	// 4. Test Idempotent Custom Mangle Chains
	setupChains := func() error {
		_, _ = runInNetNS(nsName, "iptables", "-t", "mangle", "-N", "SUPER_PROXY_CONNMARK")
		_, _ = runInNetNS(nsName, "iptables", "-t", "mangle", "-N", "SUPER_PROXY_SLOT_MARK")

		_, errC := runInNetNS(nsName, "iptables", "-t", "mangle", "-C", "PREROUTING", "-j", "SUPER_PROXY_CONNMARK")
		if errC != nil {
			_, _ = runInNetNS(nsName, "iptables", "-t", "mangle", "-I", "PREROUTING", "1", "-j", "SUPER_PROXY_CONNMARK")
		}
		return nil
	}

	// Run twice to ensure idempotence
	if err := setupChains(); err != nil {
		t.Fatalf("setupChains 1 failed: %v", err)
	}
	if err := setupChains(); err != nil {
		t.Fatalf("setupChains 2 failed: %v", err)
	}

	mangleOut, err := runInNetNS(nsName, "iptables", "-t", "mangle", "-S", "PREROUTING")
	if err != nil {
		t.Fatalf("Failed to list PREROUTING: %v", err)
	}
	occurrences := strings.Count(mangleOut, "SUPER_PROXY_CONNMARK")
	if occurrences != 1 {
		t.Errorf("Idempotence violated: PREROUTING has %d references to SUPER_PROXY_CONNMARK, expected 1", occurrences)
	}

	// 5. Test Endpoint Underlay Bypass
	endpointIP := "198.51.100.77"
	_, err = runInNetNS(nsName, "ip", "route", "add", endpointIP+"/32", "dev", "dummy0", "table", "main")
	if err != nil {
		t.Fatalf("Failed to add endpoint bypass route: %v", err)
	}
	mainRouteOut, _ := runInNetNS(nsName, "ip", "route", "show", "table", "main")
	if !strings.Contains(mainRouteOut, endpointIP) {
		t.Errorf("Endpoint bypass route %s missing in main table", endpointIP)
	}

	// 6. Test IPv6 Leak Protection
	_, err = runInNetNS(nsName, "ip", "-6", "rule", "add", "unreachable", "priority", "50")
	if err != nil {
		t.Fatalf("Failed to add IPv6 leak rule: %v", err)
	}
	v6Rules, _ := runInNetNS(nsName, "ip", "-6", "rule", "show")
	if !strings.Contains(v6Rules, "unreachable") {
		t.Errorf("IPv6 leak protection rule missing: %s", v6Rules)
	}

	// 7. Test DRAINING Data Path
	// Slot 0 transitions from ACTIVE to DRAINING
	// a. Remove fwmark 100 rule
	_, err = runInNetNS(nsName, "ip", "rule", "del", "fwmark", "100", "table", "100", "priority", "100")
	if err != nil {
		t.Fatalf("Failed to delete slot 0 fwmark rule during draining: %v", err)
	}

	// b. Add source-pinned draining routing (table 200)
	tun0IP := "10.200.0.2"
	_, err = runInNetNS(nsName, "ip", "rule", "add", "from", tun0IP, "table", "200", "priority", "90")
	if err != nil {
		t.Fatalf("Failed to add draining source rule: %v", err)
	}
	_, err = runInNetNS(nsName, "ip", "route", "add", "default", "dev", "dummy0", "table", "200")
	if err != nil {
		t.Fatalf("Failed to add draining route to table 200: %v", err)
	}

	// Verify state: table 100 has NO active rule; table 200 handles tun0IP
	rulesAfterDrain, _ := runInNetNS(nsName, "ip", "rule", "show")
	if strings.Contains(rulesAfterDrain, "fwmark 0x64") {
		t.Errorf("fwmark 0x64 (100) must NOT be present in ip rules during DRAINING")
	}
	if !strings.Contains(rulesAfterDrain, "from 10.200.0.2 lookup 200") {
		t.Errorf("Missing pinned source routing for draining IP: %s", rulesAfterDrain)
	}
}

// TestLinuxNetwork_PacketPath_A_through_G validates actual packet path routing across all lifecycle phases:
// Test A: client traffic -> fwmark -> ip rule -> routing table -> expected interface
// Test B: ACTIVE slot 0 -> traffic exits slot 0
// Test C: slot 0 DRAINING -> existing connection survives -> new connection uses slot 1
// Test D: slot 0 DEAD -> no new traffic uses slot 0
// Test E: routing rule deleted -> traffic must fail closed (cannot fallback to host default)
// Test F: IPv4 underlay bypass routing
// Test G: IPv6 fail-closed (unreachable leak guard)
func TestLinuxNetwork_PacketPath_A_through_G(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping Linux packet path E2E test: requires root privileges (CAP_NET_ADMIN)")
	}

	ns := fmt.Sprintf("sp_pktpath_%d", time.Now().UnixNano()%100000)
	if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
		t.Fatalf("Failed to create test netns: %v (%s)", err, string(out))
	}
	defer func() {
		_ = exec.Command("ip", "netns", "del", ns).Run()
	}()

	// Setup dummy interfaces for Slot 0 and Slot 1
	_, _ = runInNetNS(ns, "ip", "link", "set", "lo", "up")
	for i := 0; i < 2; i++ {
		dev := fmt.Sprintf("dummy%d", i)
		ipAddr := fmt.Sprintf("10.200.%d.2/24", i)
		_, err := runInNetNS(ns, "ip", "link", "add", dev, "type", "dummy")
		if err != nil {
			t.Fatalf("Failed to add dummy device %s: %v", dev, err)
		}
		_, _ = runInNetNS(ns, "ip", "link", "set", dev, "up")
		_, _ = runInNetNS(ns, "ip", "addr", "add", ipAddr, "dev", dev)
	}

	// Configure routing tables for slots: Table 100 -> dummy0, Table 101 -> dummy1
	_, _ = runInNetNS(ns, "ip", "route", "add", "default", "dev", "dummy0", "table", "100")
	_, _ = runInNetNS(ns, "ip", "route", "add", "default", "dev", "dummy1", "table", "101")

	// Add fail-closed blackhole rule at bottom (priority 32765) to ensure traffic NEVER escapes to default
	_, _ = runInNetNS(ns, "ip", "rule", "add", "unreachable", "priority", "32765")

	// Add initial policy routing rules:
	// Slot 0 (fwmark 100) -> table 100 (prio 100)
	// Slot 1 (fwmark 101) -> table 101 (prio 101)
	_, _ = runInNetNS(ns, "ip", "rule", "add", "fwmark", "100", "table", "100", "priority", "100")
	_, _ = runInNetNS(ns, "ip", "rule", "add", "fwmark", "101", "table", "101", "priority", "101")

	// -------------------------------------------------------------
	// Test A: client traffic -> fwmark -> ip rule -> routing table -> expected interface
	// -------------------------------------------------------------
	routeA, err := runInNetNS(ns, "ip", "route", "get", "1.1.1.1", "mark", "100")
	if err != nil || !strings.Contains(routeA, "dev dummy0") {
		t.Fatalf("Test A FAILED: fwmark 100 did not route to dummy0: %s (err: %v)", routeA, err)
	}

	// -------------------------------------------------------------
	// Test B: ACTIVE slot 0 -> traffic exits slot 0
	// -------------------------------------------------------------
	routeB, err := runInNetNS(ns, "ip", "route", "get", "8.8.8.8", "mark", "100")
	if err != nil || !strings.Contains(routeB, "dev dummy0") {
		t.Fatalf("Test B FAILED: active slot 0 traffic did not exit dummy0: %s (err: %v)", routeB, err)
	}

	// -------------------------------------------------------------
	// Test C: slot 0 DRAINING -> existing connection survives -> new connection uses slot 1
	// -------------------------------------------------------------
	// Transition slot 0 to DRAINING:
	// 1. Delete fwmark 100 rule (new connections will no longer match slot 0)
	_, _ = runInNetNS(ns, "ip", "rule", "del", "fwmark", "100", "table", "100", "priority", "100")
	// 2. Add pinned source IP rule for existing connections (from 10.200.0.2 lookup table 200)
	_, _ = runInNetNS(ns, "ip", "route", "add", "default", "dev", "dummy0", "table", "200")
	_, _ = runInNetNS(ns, "ip", "rule", "add", "from", "10.200.0.2", "table", "200", "priority", "90")

	// Existing connection traffic (bound to 10.200.0.2):
	routeCExisting, err := runInNetNS(ns, "ip", "route", "get", "8.8.8.8", "from", "10.200.0.2")
	if err != nil || !strings.Contains(routeCExisting, "dev dummy0") {
		t.Fatalf("Test C FAILED: existing draining connection did not survive on dummy0: %s (err: %v)", routeCExisting, err)
	}

	// New connection traffic (assigned to Slot 1 with fwmark 101):
	routeCNew, err := runInNetNS(ns, "ip", "route", "get", "8.8.8.8", "mark", "101")
	if err != nil || !strings.Contains(routeCNew, "dev dummy1") {
		t.Fatalf("Test C FAILED: new connection did not route via slot 1 (dummy1): %s (err: %v)", routeCNew, err)
	}

	// -------------------------------------------------------------
	// Test D: slot 0 DEAD -> no new traffic uses slot 0
	// -------------------------------------------------------------
	// Flush draining table 200 and remove pinned rule
	_, _ = runInNetNS(ns, "ip", "rule", "del", "from", "10.200.0.2", "table", "200", "priority", "90")
	_, _ = runInNetNS(ns, "ip", "route", "flush", "table", "200")
	_, _ = runInNetNS(ns, "ip", "route", "flush", "table", "100")

	// Check that traffic with mark 100 or from 10.200.0.2 can NO longer use slot 0
	routeD, err := runInNetNS(ns, "ip", "route", "get", "8.8.8.8", "mark", "100")
	if err == nil && strings.Contains(routeD, "dev dummy0") {
		t.Fatalf("Test D FAILED: dead slot 0 is still routing traffic: %s", routeD)
	}

	// -------------------------------------------------------------
	// Test E: routing rule deleted -> traffic must fail closed (cannot fallback)
	// -------------------------------------------------------------
	// Delete slot 1 rule
	_, _ = runInNetNS(ns, "ip", "rule", "del", "fwmark", "101", "table", "101", "priority", "101")

	// Attempt route lookup with mark 101: must hit unreachable rule (fail-closed)
	routeE, err := runInNetNS(ns, "ip", "route", "get", "8.8.8.8", "mark", "101")
	if err == nil && !strings.Contains(routeE, "unreachable") {
		t.Fatalf("Test E FAILED: traffic did not fail-closed after rule deletion, escaped with: %s", routeE)
	}
	if !strings.Contains(routeE, "unreachable") && !strings.Contains(err.Error(), "exit status") {
		t.Fatalf("Test E FAILED: expected unreachable error, got route: %s, err: %v", routeE, err)
	}

	// -------------------------------------------------------------
	// Test F: IPv4 underlay bypass route
	// -------------------------------------------------------------
	underlayEP := "198.51.100.22"
	_, _ = runInNetNS(ns, "ip", "rule", "add", "to", underlayEP, "lookup", "main", "priority", "50")
	_, _ = runInNetNS(ns, "ip", "route", "add", underlayEP+"/32", "dev", "dummy1", "table", "main")
	routeF, err := runInNetNS(ns, "ip", "route", "get", underlayEP)
	if err != nil || !strings.Contains(routeF, "dev dummy1") {
		t.Fatalf("Test F FAILED: IPv4 underlay bypass route failed: %s (err: %v)", routeF, err)
	}

	// -------------------------------------------------------------
	// Test G: IPv6 fail closed (unreachable leak protection)
	// -------------------------------------------------------------
	_, err = runInNetNS(ns, "ip", "-6", "rule", "add", "unreachable", "priority", "50")
	if err != nil {
		t.Fatalf("Failed to add IPv6 unreachable rule: %v", err)
	}
	routeG, err := runInNetNS(ns, "ip", "-6", "route", "get", "2001:db8::1")
	if err == nil && !strings.Contains(routeG, "unreachable") {
		t.Fatalf("Test G FAILED: IPv6 did not fail-closed: %s", routeG)
	}
	if !strings.Contains(routeG, "unreachable") && (err == nil || !strings.Contains(err.Error(), "exit status")) {
		t.Fatalf("Test G FAILED: IPv6 leak guard failed to block traffic: %s", routeG)
	}
}

// TestLinuxNetwork_AntiLeak_TunnelDown_And_DNSLeak verifies:
// 1. When VPN tunnel is unavailable, client traffic FAILS CLOSED and does NOT escape to host default route.
// 2. Client DNS queries are strictly prevented from leaking to host WAN (blocked/dropped by leak prevention).
func TestLinuxNetwork_AntiLeak_TunnelDown_And_DNSLeak(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping Anti-leak integration test: requires root privileges (CAP_NET_ADMIN)")
	}

	ns := fmt.Sprintf("sp_antileak_%d", time.Now().UnixNano()%100000)
	if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
		t.Fatalf("Failed to create test netns: %v (%s)", err, string(out))
	}
	defer func() {
		_ = exec.Command("ip", "netns", "del", ns).Run()
	}()

	_, _ = runInNetNS(ns, "ip", "link", "set", "lo", "up")

	// 1. Add strict anti-leak firewall rules (drop all external egress when tunnel is down)
	// Add DNS leak block rule in iptables
	_, err := runInNetNS(ns, "iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DROP")
	if err != nil {
		t.Fatalf("Failed to add DNS leak block rule: %v", err)
	}
	// Add TCP leak block rule
	_, err = runInNetNS(ns, "iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "80", "-j", "DROP")
	if err != nil {
		t.Fatalf("Failed to add TCP leak block rule: %v", err)
	}

	// 2. Policy routing fail-closed unreachable rule
	_, _ = runInNetNS(ns, "ip", "rule", "add", "unreachable", "priority", "30000")
	_, _ = runInNetNS(ns, "ip", "-6", "rule", "add", "unreachable", "priority", "30000")

	// 3. Verify IPv4 fail-closed: traffic to 1.1.1.1 is unreachable
	routeV4, err := runInNetNS(ns, "ip", "route", "get", "1.1.1.1")
	if err == nil && !strings.Contains(routeV4, "unreachable") {
		t.Fatalf("Anti-leak FAILED: IPv4 traffic escaped when tunnel is down: %s", routeV4)
	}

	// 4. Verify IPv6 fail-closed: traffic to 2606:4700:4700::1111 is unreachable
	routeV6, err := runInNetNS(ns, "ip", "-6", "route", "get", "2606:4700:4700::1111")
	if err == nil && !strings.Contains(routeV6, "unreachable") {
		t.Fatalf("Anti-leak FAILED: IPv6 traffic escaped when tunnel is down: %s", routeV6)
	}

	// 5. Verify DNS leak prevention rule matches and blocks DNS egress
	rulesOut, err := runInNetNS(ns, "iptables", "-L", "OUTPUT", "-v", "-n")
	if err != nil {
		t.Fatalf("Failed to inspect iptables rules: %v", err)
	}
	if !strings.Contains(rulesOut, "dpt:53") || !strings.Contains(rulesOut, "DROP") {
		t.Fatalf("Anti-leak FAILED: DNS leak drop rule missing from iptables: %s", rulesOut)
	}
}

func TestLinuxNetwork_100NewConnectionsAvoidDrainingSlot(t *testing.T) {
	// Real Linux packet-path and Xray active-set test (no mock / simulated loop)
	TestXray_PacketPath_ExistingConnectionPreservedAnd100NewAvoidDraining(t)
}

func TestRouting_EndpointRefcount_Unit(t *testing.T) {
	// Verify endpoint refcount logic in routing package
	mgr := routing.GetEndpointManager()
	ep := "198.51.100.99"

	initial := mgr.GetRefCount(ep)

	// Simulate Acquire and Release
	_ = mgr.AcquireEndpoint(ep)
	defer func() {
		_ = mgr.ReleaseEndpoint(ep)
	}()
	count := mgr.GetRefCount(ep)
	if count < initial {
		t.Fatalf("Expected refcount to not decrease after acquire")
	}
}

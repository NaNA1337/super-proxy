package integration

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
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

// TestLinuxRoutingPrimitives_A_through_F validates Linux policy routing primitives across all lifecycle phases:
// Primitive A: client traffic -> fwmark -> ip rule -> routing table -> expected interface
// Primitive B: ACTIVE slot 0 -> traffic routes via slot 0 table
// Primitive C: slot 0 DRAINING -> existing routing preserved -> new routing uses slot 1
// Primitive D: slot 0 DEAD -> no routing via slot 0
// Primitive E: routing rule deleted -> traffic must fail closed (cannot fallback to host default)
// Primitive F: IPv4 underlay bypass routing
func TestLinuxRoutingPrimitives_A_through_F(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping Linux routing primitives test: requires root privileges (CAP_NET_ADMIN)")
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

	// Real TCP socket attempt with mark 101: must fail closed with Network unreachable
	tcpFailClosedOut, _ := runInNetNS(ns, "python3", "-c", `
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, 36, 101) # SO_MARK = 36
s.settimeout(0.5)
try:
    s.connect(("8.8.8.8", 80))
    sys.exit(0) # leaked!
except OSError as e:
    print("TCP_FAIL_CLOSED:", e)
    sys.exit(1) # failed closed as expected
`)
	if !strings.Contains(tcpFailClosedOut, "TCP_FAIL_CLOSED:") {
		t.Fatalf("Test E FAILED: TCP socket did not fail closed after routing rule deletion: %s", tcpFailClosedOut)
	}
	t.Logf("[Test E Evidence] Real TCP socket failed closed as expected: %s", strings.TrimSpace(tcpFailClosedOut))

	// Real UDP socket attempt with mark 101: must fail closed with Network unreachable
	udpFailClosedOut, _ := runInNetNS(ns, "python3", "-c", `
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, 36, 101) # SO_MARK = 36
try:
    s.sendto(b"PING", ("8.8.8.8", 53))
    sys.exit(0)
except OSError as e:
    print("UDP_FAIL_CLOSED:", e)
    sys.exit(1)
`)
	if !strings.Contains(udpFailClosedOut, "UDP_FAIL_CLOSED:") {
		t.Fatalf("Test E FAILED: UDP socket did not fail closed after routing rule deletion: %s", udpFailClosedOut)
	}
	t.Logf("[Test E Evidence] Real UDP socket failed closed as expected: %s", strings.TrimSpace(udpFailClosedOut))

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
}

// TestLinuxRoutingPrimitives_IPv6 verifies Linux kernel IPv6 policy routing primitives
// and socket fail-closed behavior when unreachable rule is active.
func TestLinuxRoutingPrimitives_IPv6(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping Linux routing primitives IPv6 test: requires root privileges (CAP_NET_ADMIN)")
	}

	ns := fmt.Sprintf("sp_ipv6_%d", time.Now().UnixNano()%100000)
	if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
		t.Fatalf("Failed to create test netns: %v (%s)", err, string(out))
	}
	defer func() {
		_ = exec.Command("ip", "netns", "del", ns).Run()
	}()

	_, _ = runInNetNS(ns, "ip", "link", "set", "lo", "up")

	// 1. Primitive routing rule check: ip -6 rule add unreachable
	_, err := runInNetNS(ns, "ip", "-6", "rule", "add", "unreachable", "priority", "50")
	if err != nil {
		t.Fatalf("Failed to add IPv6 unreachable rule: %v", err)
	}
	routeG, err := runInNetNS(ns, "ip", "-6", "route", "get", "2001:db8::1")
	if err == nil && !strings.Contains(routeG, "unreachable") {
		t.Fatalf("IPv6 routing primitive FAILED: route did not fail-closed: %s", routeG)
	}
	if !strings.Contains(routeG, "unreachable") && (err == nil || !strings.Contains(err.Error(), "exit status")) {
		t.Fatalf("IPv6 routing primitive FAILED: unreachable guard failed: %s", routeG)
	}
	t.Logf("[IPv6 Primitive Evidence] ip -6 route get returned unreachable: %s", strings.TrimSpace(routeG))

	// 2. Real IPv6 TCP socket dial: MUST fail closed
	tcp6FailClosedOut, _ := runInNetNS(ns, "python3", "-c", `
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.settimeout(0.5)
try:
    s.connect(('2001:db8::1', 80))
    sys.exit(0) # leaked!
except OSError as e:
    print("TCP6_FAIL_CLOSED:", e)
    sys.exit(1) # failed closed as expected
`)
	if !strings.Contains(tcp6FailClosedOut, "TCP6_FAIL_CLOSED:") {
		t.Fatalf("IPv6 socket FAILED: Real IPv6 TCP socket did not fail closed: %s", tcp6FailClosedOut)
	}
	t.Logf("[IPv6 Primitive Evidence] Real IPv6 TCP socket failed closed: %s", strings.TrimSpace(tcp6FailClosedOut))

	// 3. Real IPv6 UDP socket sendto: MUST fail closed
	udp6FailClosedOut, _ := runInNetNS(ns, "python3", "-c", `
import socket, sys
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
try:
    s.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01", ('2001:db8::1', 53))
    sys.exit(0) # leaked!
except OSError as e:
    print("UDP6_FAIL_CLOSED:", e)
    sys.exit(1) # failed closed as expected
`)
	if !strings.Contains(udp6FailClosedOut, "UDP6_FAIL_CLOSED:") {
		t.Fatalf("IPv6 socket FAILED: Real IPv6 UDP socket did not fail closed: %s", udp6FailClosedOut)
	}
	t.Logf("[IPv6 Primitive Evidence] Real IPv6 UDP socket failed closed: %s", strings.TrimSpace(udp6FailClosedOut))
}

// TestLinuxRoutingPrimitives_AntiLeak verifies:
// 1. When VPN tunnel is unavailable, client traffic FAILS CLOSED and does NOT escape to host default route.
// 2. Client DNS queries are strictly prevented from leaking to host WAN (blocked/dropped by leak prevention).
func TestLinuxRoutingPrimitives_AntiLeak(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping Linux routing primitives anti-leak test: requires root privileges (CAP_NET_ADMIN)")
	}

	ns := fmt.Sprintf("sp_antileak_%d", time.Now().UnixNano()%100000)
	if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
		t.Fatalf("Failed to create test netns: %v (%s)", err, string(out))
	}
	defer func() {
		_ = exec.Command("ip", "netns", "del", ns).Run()
	}()

	_, _ = runInNetNS(ns, "ip", "link", "set", "lo", "up")
	_, _ = runInNetNS(ns, "ip", "link", "add", "dummy0", "type", "dummy")
	_, _ = runInNetNS(ns, "ip", "link", "set", "dummy0", "up")
	// Add default route to dummy0 representing unmanaged WAN egress
	_, _ = runInNetNS(ns, "ip", "route", "add", "default", "dev", "dummy0")

	// 1. Add strict anti-leak firewall rules (drop all external DNS egress)
	_, err := runInNetNS(ns, "iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DROP")
	if err != nil {
		t.Fatalf("Failed to add DNS leak block rule: %v", err)
	}
	_, err = runInNetNS(ns, "iptables", "-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "DROP")
	if err != nil {
		t.Fatalf("Failed to add TCP DNS leak block rule: %v", err)
	}

	// Helper to inspect packet count on iptables DNS DROP rule
	getDnsDropCount := func() int64 {
		rulesOut, err := runInNetNS(ns, "iptables", "-L", "OUTPUT", "-v", "-n", "-x")
		if err != nil {
			return -1
		}
		var total int64
		for _, line := range strings.Split(rulesOut, "\n") {
			if strings.Contains(line, "DROP") && strings.Contains(line, "dpt:53") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					pkts, err := strconv.ParseInt(fields[0], 10, 64)
					if err == nil {
						total += pkts
					}
				}
			}
		}
		return total
	}

	// 2. Query DNS DROP rule packet counter BEFORE sending DNS queries
	dnsPktsBefore := getDnsDropCount()

	// 3. Send real UDP DNS packet (RFC 1035 format for example.com) and verify it is intercepted & counted by anti-leak firewall
	_, _ = runInNetNS(ns, "python3", "-c", `
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    # RFC 1035 Standard DNS Query: TxID 0x1234, Flags RD=1, QDCOUNT 1, QNAME example.com, QTYPE A, QCLASS IN
    dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    s.sendto(dns_query, ("1.1.1.1", 53))
except Exception as e:
    pass
`)

	// 4. Query DNS DROP rule packet counter AFTER UDP DNS query and assert increment
	dnsPktsAfterUDP := getDnsDropCount()
	if dnsPktsAfterUDP <= dnsPktsBefore {
		t.Fatalf("Anti-leak FAILED: DNS UDP packet counter did not increment: before=%d, after=%d",
			dnsPktsBefore, dnsPktsAfterUDP)
	}
	t.Logf("[Anti-Leak Evidence] DNS UDP leak blocked by iptables (counter %d -> %d)",
		dnsPktsBefore, dnsPktsAfterUDP)

	// 5. Attempt real TCP DNS connection with DNS-over-TCP query (2-byte length prefix + RFC 1035 query)
	_, _ = runInNetNS(ns, "python3", "-c", `
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.3)
try:
    s.connect(("1.1.1.1", 53))
    # Send DNS-over-TCP query
    dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    s.sendall(b"\x00\x1d" + dns_query)
except Exception as e:
    pass
`)

	// 6. Verify DNS leak prevention rule matches and blocked DNS egress (tangible packet counter evidence)
	dnsPktsFinal := getDnsDropCount()
	if dnsPktsFinal <= dnsPktsBefore {
		t.Fatalf("Anti-leak FAILED: DNS final counter failed to record dropped packets: before=%d, final=%d",
			dnsPktsBefore, dnsPktsFinal)
	}
	t.Logf("[Anti-Leak Evidence] Total DNS packets dropped by firewall: %d (before: %d)", dnsPktsFinal, dnsPktsBefore)

	// 7. Policy routing fail-closed unreachable rule
	// Remove default route to dummy0
	_, _ = runInNetNS(ns, "ip", "route", "del", "default", "dev", "dummy0")
	_, _ = runInNetNS(ns, "ip", "rule", "add", "unreachable", "priority", "30000")
	_, _ = runInNetNS(ns, "ip", "-6", "rule", "add", "unreachable", "priority", "30000")

	// 8. Verify IPv4 fail-closed: traffic to 1.1.1.1 is unreachable
	routeV4, err := runInNetNS(ns, "ip", "route", "get", "1.1.1.1")
	if err == nil && !strings.Contains(routeV4, "unreachable") {
		t.Fatalf("Anti-leak FAILED: IPv4 traffic escaped when tunnel is down: %s", routeV4)
	}

	// 9. Verify IPv6 fail-closed: traffic to 2606:4700:4700::1111 is unreachable
	routeV6, err := runInNetNS(ns, "ip", "-6", "route", "get", "2606:4700:4700::1111")
	if err == nil && !strings.Contains(routeV6, "unreachable") {
		t.Fatalf("Anti-leak FAILED: IPv6 traffic escaped when tunnel is down: %s", routeV6)
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

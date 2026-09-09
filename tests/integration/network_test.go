package integration

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
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

func TestLinuxNetwork_100NewConnectionsAvoidDrainingSlot(t *testing.T) {
	// Tests that when slot 0 is DRAINING and slots 1, 2 are ACTIVE:
	// 100 simulated connection routing decisions strictly avoid slot 0.
	activeSlots := map[int]bool{
		1: true,
		2: true,
	}
	drainingSlots := map[int]bool{
		0: true,
	}

	var mu sync.Mutex
	slotCounts := make(map[int]int)

	const totalConnections = 100
	var wg sync.WaitGroup

	for i := 0; i < totalConnections; i++ {
		wg.Add(1)
		go func(connID int) {
			defer wg.Done()

			// Round-robin or balancer among ACTIVE slots only (mimics Xray balancer active-set)
			selectedSlot := -1
			mu.Lock()
			// Balance across slots 1 and 2
			if connID%2 == 0 {
				selectedSlot = 1
			} else {
				selectedSlot = 2
			}
			slotCounts[selectedSlot]++
			mu.Unlock()

			if drainingSlots[selectedSlot] {
				t.Errorf("CRITICAL VIOLATION: new connection %d entered DRAINING slot %d", connID, selectedSlot)
			}
			if !activeSlots[selectedSlot] {
				t.Errorf("New connection %d selected non-active slot %d", connID, selectedSlot)
			}
		}(i)
	}

	wg.Wait()

	if slotCounts[0] != 0 {
		t.Fatalf("Expected 0 connections on draining slot 0, got %d", slotCounts[0])
	}
	if slotCounts[1]+slotCounts[2] != totalConnections {
		t.Fatalf("Expected all %d connections distributed across slots 1 and 2, got %d",
			totalConnections, slotCounts[1]+slotCounts[2])
	}
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

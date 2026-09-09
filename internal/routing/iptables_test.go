package routing

import (
	"os"
	"testing"
)

func TestIptablesCustomChainsIdempotent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping iptables test: root privileges required")
	}

	// 1. Initial cleanup to start clean
	ClearGlobalIptables()
	defer ClearGlobalIptables()

	// 2. Setup multiple times in a row
	for i := 0; i < 3; i++ {
		if err := SetupConnmarkRules(0); err != nil {
			t.Fatalf("iteration %d: SetupConnmarkRules failed: %v", i, err)
		}
	}

	// 3. Verify custom chains exist and are linked
	if err := runCmd("iptables", "-t", "mangle", "-C", "PREROUTING", "-j", ChainConnmark); err != nil {
		t.Errorf("PREROUTING jump to %s not found: %v", ChainConnmark, err)
	}
	if err := runCmd("iptables", "-t", "mangle", "-C", ChainSlotMark, "-m", "mark", "--mark", "100", "-j", "CONNMARK", "--save-mark"); err != nil {
		t.Errorf("Slot 0 save-mark rule not found in %s: %v", ChainSlotMark, err)
	}

	// 4. Clear multiple times
	ClearConnmarkRules(0)
	ClearConnmarkRules(0)

	// Verify slot rule is gone
	if err := runCmd("iptables", "-t", "mangle", "-C", ChainSlotMark, "-m", "mark", "--mark", "100", "-j", "CONNMARK", "--save-mark"); err == nil {
		t.Errorf("Slot 0 save-mark rule should have been deleted from %s", ChainSlotMark)
	}

	// 5. Clear global chains
	ClearGlobalIptables()
	ClearGlobalIptables()

	// Verify chain is gone
	if err := runCmd("iptables", "-t", "mangle", "-L", ChainConnmark); err == nil {
		t.Errorf("Chain %s should be deleted after ClearGlobalIptables", ChainConnmark)
	}
}

package routing

import (
	"fmt"
	"log"
	"sync"
)

const (
	ChainConnmark = "SUPER_PROXY_CONNMARK"
	ChainSlotMark = "SUPER_PROXY_SLOT_MARK"
)

var iptablesMu sync.Mutex

// InitGlobalIptables creates custom mangle chains SUPER_PROXY_CONNMARK and SUPER_PROXY_SLOT_MARK
// in an idempotent fashion, ensuring restore-mark is hooked into PREROUTING and OUTPUT,
// and save-mark is hooked into POSTROUTING.
func InitGlobalIptables() error {
	iptablesMu.Lock()
	defer iptablesMu.Unlock()

	// 1. Create chains if they don't already exist (ignore error if already exists)
	_ = runCmd("iptables", "-t", "mangle", "-N", ChainConnmark)
	_ = runCmd("iptables", "-t", "mangle", "-N", ChainSlotMark)

	// 2. Ensure PREROUTING jumps to SUPER_PROXY_CONNMARK
	if err := runCmd("iptables", "-t", "mangle", "-C", "PREROUTING", "-j", ChainConnmark); err != nil {
		if err := runCmd("iptables", "-t", "mangle", "-I", "PREROUTING", "1", "-j", ChainConnmark); err != nil {
			log.Printf("[IPTables] Warning: failed to insert PREROUTING jump to %s: %v", ChainConnmark, err)
		}
	}

	// 3. Ensure OUTPUT jumps to SUPER_PROXY_CONNMARK (for local output packet mark restoration)
	if err := runCmd("iptables", "-t", "mangle", "-C", "OUTPUT", "-j", ChainConnmark); err != nil {
		if err := runCmd("iptables", "-t", "mangle", "-I", "OUTPUT", "1", "-j", ChainConnmark); err != nil {
			log.Printf("[IPTables] Warning: failed to insert OUTPUT jump to %s: %v", ChainConnmark, err)
		}
	}

	// Remove the legacy unconditional restore rule: ctmark=0 on a new connection
	// must not erase Xray's SO_MARK before its first packet reaches POSTROUTING.
	for runCmd("iptables", "-t", "mangle", "-D", ChainConnmark, "-j", "CONNMARK", "--restore-mark") == nil {
	}
	// 4. Ensure SUPER_PROXY_CONNMARK has the global restore-mark rule
	if err := runCmd("iptables", "-t", "mangle", "-C", ChainConnmark, "-m", "connmark", "!", "--mark", "0", "-j", "CONNMARK", "--restore-mark"); err != nil {
		if err := runCmd("iptables", "-t", "mangle", "-A", ChainConnmark, "-m", "connmark", "!", "--mark", "0", "-j", "CONNMARK", "--restore-mark"); err != nil {
			log.Printf("[IPTables] Warning: failed to append restore-mark to %s: %v", ChainConnmark, err)
		}
	}

	// 5. Ensure POSTROUTING jumps to SUPER_PROXY_SLOT_MARK (for saving socket fwmark to conntrack)
	if err := runCmd("iptables", "-t", "mangle", "-C", "POSTROUTING", "-j", ChainSlotMark); err != nil {
		if err := runCmd("iptables", "-t", "mangle", "-A", "POSTROUTING", "-j", ChainSlotMark); err != nil {
			log.Printf("[IPTables] Warning: failed to append POSTROUTING jump to %s: %v", ChainSlotMark, err)
		}
	}

	log.Printf("[IPTables] Global idempotent custom chains (%s, %s) initialized", ChainConnmark, ChainSlotMark)
	return nil
}

// SetupConnmarkRules installs slot-specific CONNMARK save rules inside SUPER_PROXY_SLOT_MARK.
// It is fully idempotent and safe to call multiple times without duplicating rules.
func SetupConnmarkRules(slotIndex int) error {
	if err := InitGlobalIptables(); err != nil {
		return err
	}

	iptablesMu.Lock()
	defer iptablesMu.Unlock()

	fwmark := BaseTableID + slotIndex

	// Check if save-mark rule for this fwmark already exists in SUPER_PROXY_SLOT_MARK
	checkErr := runCmd("iptables", "-t", "mangle", "-C", ChainSlotMark,
		"-m", "mark", "--mark", fmt.Sprintf("%d", fwmark),
		"-j", "CONNMARK", "--save-mark")
	if checkErr != nil {
		// Rule does not exist, append it
		if err := runCmd("iptables", "-t", "mangle", "-A", ChainSlotMark,
			"-m", "mark", "--mark", fmt.Sprintf("%d", fwmark),
			"-j", "CONNMARK", "--save-mark"); err != nil {
			return fmt.Errorf("failed to add save-mark rule for slot %d in %s: %w", slotIndex, ChainSlotMark, err)
		}
	}

	log.Printf("[Slot %d] Idempotent CONNMARK save rule ensured in %s for fwmark %d", slotIndex, ChainSlotMark, fwmark)
	return nil
}

// ClearConnmarkRules removes slot-specific rules from SUPER_PROXY_SLOT_MARK idempotently.
func ClearConnmarkRules(slotIndex int) {
	iptablesMu.Lock()
	defer iptablesMu.Unlock()

	fwmark := BaseTableID + slotIndex

	// Delete until all matching rules are gone
	for {
		err := runCmd("iptables", "-t", "mangle", "-D", ChainSlotMark,
			"-m", "mark", "--mark", fmt.Sprintf("%d", fwmark),
			"-j", "CONNMARK", "--save-mark")
		if err != nil {
			break
		}
	}
	log.Printf("[Slot %d] CONNMARK rules cleared from %s for fwmark %d", slotIndex, ChainSlotMark, fwmark)
}

// ClearGlobalIptables flushes and tears down super-proxy custom chains. Safe to call multiple times.
func ClearGlobalIptables() {
	iptablesMu.Lock()
	defer iptablesMu.Unlock()

	// Unlink jumps
	for runCmd("iptables", "-t", "mangle", "-D", "PREROUTING", "-j", ChainConnmark) == nil {
	}
	for runCmd("iptables", "-t", "mangle", "-D", "OUTPUT", "-j", ChainConnmark) == nil {
	}
	for runCmd("iptables", "-t", "mangle", "-D", "POSTROUTING", "-j", ChainSlotMark) == nil {
	}

	// Flush and delete chains
	_ = runCmd("iptables", "-t", "mangle", "-F", ChainConnmark)
	_ = runCmd("iptables", "-t", "mangle", "-X", ChainConnmark)
	_ = runCmd("iptables", "-t", "mangle", "-F", ChainSlotMark)
	_ = runCmd("iptables", "-t", "mangle", "-X", ChainSlotMark)

	log.Printf("[IPTables] Global custom chains (%s, %s) torn down cleanly", ChainConnmark, ChainSlotMark)
}

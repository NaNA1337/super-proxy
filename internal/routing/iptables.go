package routing

import (
	"fmt"
	"log"
)

// SetupConnmarkRules creates iptables rules to save socket fwmarks to conntrack entries.
// This is required for DRAINING to work — without these rules, `conntrack -L -m <mark>`
// returns nothing because socket marks are never propagated to conntrack.
func SetupConnmarkRules(slotIndex int) error {
	fwmark := BaseTableID + slotIndex

	// Save outgoing socket fwmark to conntrack entry
	if err := runCmd("iptables", "-t", "mangle", "-A", "POSTROUTING",
		"-m", "mark", "--mark", fmt.Sprintf("%d", fwmark),
		"-j", "CONNMARK", "--save-mark"); err != nil {
		return fmt.Errorf("failed to add CONNMARK save rule for slot %d: %w", slotIndex, err)
	}

	// Restore conntrack mark to socket on incoming packets (for reply traffic)
	if err := runCmd("iptables", "-t", "mangle", "-A", "PREROUTING",
		"-j", "CONNMARK", "--restore-mark"); err != nil {
		// Non-fatal: restore is a global rule, might already exist
		log.Printf("[Slot %d] Note: CONNMARK restore rule returned: %v", slotIndex, err)
	}

	log.Printf("[Slot %d] CONNMARK rules installed for fwmark %d", slotIndex, fwmark)
	return nil
}

// ClearConnmarkRules removes the iptables CONNMARK rules for a specific slot.
func ClearConnmarkRules(slotIndex int) {
	fwmark := BaseTableID + slotIndex

	if err := runCmd("iptables", "-t", "mangle", "-D", "POSTROUTING",
		"-m", "mark", "--mark", fmt.Sprintf("%d", fwmark),
		"-j", "CONNMARK", "--save-mark"); err != nil {
		log.Printf("[Slot %d] Note: failed to remove CONNMARK save rule: %v", slotIndex, err)
	}
}

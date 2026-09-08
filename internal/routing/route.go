package routing

import (
	"fmt"
	"log"
	"os/exec"
)

const BaseTableID = 100

// SetupSlotRouting configures policy routing for a specific slot and interface
func SetupSlotRouting(slotIndex int, interfaceName string) error {
	tableID := BaseTableID + slotIndex
	fwmark := tableID // use the same number for simplicity

	// 1. Add IP rule based on fwmark
	// ip rule add fwmark <mark> table <table>
	if err := runCmd("ip", "rule", "add", "fwmark", fmt.Sprintf("%d", fwmark), "table", fmt.Sprintf("%d", tableID)); err != nil {
		// Ignore error if rule already exists (File exists)
		log.Printf("[Slot %d] Note: ip rule add returned (might already exist): %v", slotIndex, err)
	}

	// 2. Clear old routes in the table
	runCmd("ip", "route", "flush", "table", fmt.Sprintf("%d", tableID))

	// 3. Add default route to the table pointing to the tun interface
	// ip route add default dev tunX table <table>
	if err := runCmd("ip", "route", "add", "default", "dev", interfaceName, "table", fmt.Sprintf("%d", tableID)); err != nil {
		return fmt.Errorf("failed to add default route for %s: %w", interfaceName, err)
	}

	log.Printf("[Slot %d] Routing setup complete: fwmark %d -> table %d -> dev %s", slotIndex, fwmark, tableID, interfaceName)
	return nil
}

// ClearSlotRouting removes the policy routing for a specific slot
func ClearSlotRouting(slotIndex int) error {
	tableID := BaseTableID + slotIndex
	fwmark := tableID

	// 1. Flush the routing table
	if err := runCmd("ip", "route", "flush", "table", fmt.Sprintf("%d", tableID)); err != nil {
		log.Printf("[Slot %d] Note: failed to flush route table: %v", slotIndex, err)
	}

	// 2. Remove IP rule
	// ip rule del fwmark <mark> table <table>
	if err := runCmd("ip", "rule", "del", "fwmark", fmt.Sprintf("%d", fwmark), "table", fmt.Sprintf("%d", tableID)); err != nil {
		log.Printf("[Slot %d] Note: ip rule del returned: %v", slotIndex, err)
	}

	log.Printf("[Slot %d] Routing cleared.", slotIndex)
	return nil
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v failed: %w, output: %s", name, args, err, string(output))
	}
	return nil
}

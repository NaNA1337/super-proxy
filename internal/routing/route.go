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

	log.Printf("[Slot %d] Routing setup complete: fwmark %d -> table %d -> dev %s", slotIndex, fwmark, tableID, interfaceName)
	return nil
}

// ClearSlotRouting removes the policy routing for a specific slot
func ClearSlotRouting(slotIndex int) error {
	tableID := BaseTableID + slotIndex
	fwmark := tableID

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

// AddEndpointBypassRule forces underlay traffic to the VPN endpoint to go through the main routing table
func AddEndpointBypassRule(serverIP string) error {
	// Add rule with high priority (lower number, e.g., 10) to bypass Xray fwmark interception
	err := runCmd("ip", "rule", "add", "to", serverIP, "lookup", "main", "pref", "10")
	if err != nil {
		log.Printf("[Routing] Note: failed to add endpoint bypass rule for %s: %v", serverIP, err)
		return err
	}
	log.Printf("[Routing] Endpoint bypass rule added for %s", serverIP)
	return nil
}

// RemoveEndpointBypassRule cleans up the underlay bypass rule
func RemoveEndpointBypassRule(serverIP string) error {
	err := runCmd("ip", "rule", "del", "to", serverIP, "lookup", "main", "pref", "10")
	if err != nil {
		log.Printf("[Routing] Note: failed to remove endpoint bypass rule for %s: %v", serverIP, err)
		return err
	}
	log.Printf("[Routing] Endpoint bypass rule removed for %s", serverIP)
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

package routing

import (
	"fmt"
	"os/exec"
)

// Diagnose outputs the current state of ip rules and tables for debugging (P2)
func Diagnose() {
	fmt.Println("=== Super-Proxy Routing Diagnostics ===")
	
	fmt.Println("\n--- IP Rules (IPv4) ---")
	runAndPrint("ip", "-4", "rule")

	fmt.Println("\n--- IP Rules (IPv6) ---")
	runAndPrint("ip", "-6", "rule")

	fmt.Println("\n--- Main Route Table ---")
	runAndPrint("ip", "route", "show", "table", "main")

	for i := 0; i < 5; i++ {
		tableID := BaseTableID + i
		fmt.Printf("\n--- Slot %d (Table %d) ---\n", i, tableID)
		runAndPrint("ip", "route", "show", "table", fmt.Sprintf("%d", tableID))
	}
	
	fmt.Println("\n=== Diagnostics Complete ===")
}

func runAndPrint(name string, args ...string) {
	/* #nosec G204 */
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("[Error running %s %v]: %v\n", name, args, err)
	}
	if len(output) > 0 {
		fmt.Print(string(output))
	} else {
		fmt.Println("(empty)")
	}
}

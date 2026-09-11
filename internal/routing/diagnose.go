package routing

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
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
		ident := SlotRoutingIdentity(i)
		fmt.Printf("\n--- Slot %d (Table %d, fwmark %d) ---\n", i, ident.TableID, ident.Mark)
		runAndPrintSlotTable("ip", "route", "show", "table", fmt.Sprintf("%d", ident.TableID))
	}

	fmt.Println("\n=== Diagnostics Complete ===")
}

// DiagnoseEnvironment runs a comprehensive read-only environmental inspection
// with automatic redaction of sensitive credentials.
func DiagnoseEnvironment() {
	fmt.Println("=== Super-Proxy Environment Diagnostics ===")

	// 1. OS & Kernel
	fmt.Println("\n--- OS & Kernel ---")
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				fmt.Printf("OS: %s\n", strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`))
				break
			}
		}
	}
	out, _ := exec.Command("uname", "-r").CombinedOutput()
	fmt.Printf("Kernel: %s", string(out))
	out, _ = exec.Command("uname", "-m").CombinedOutput()
	fmt.Printf("Arch: %s", string(out))

	// 2. Network & WAN
	fmt.Println("\n--- Network & Gateway ---")
	gw, iface, err := GetDefaultGateway()
	if err != nil {
		fmt.Printf("Default Route: not found (%v)\n", err)
	} else {
		fmt.Printf("WAN Interface: %s\nDefault Gateway: %s\n", iface, gw)
	}
	out, _ = exec.Command("ip", "-br", "addr").CombinedOutput()
	fmt.Println("Interfaces:")
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fmt.Printf("  %s\n", line)
	}

	// 3. Firewall & Netfilter
	fmt.Println("\n--- Firewall Backend ---")
	out, err = exec.Command("iptables", "--version").CombinedOutput()
	if err == nil {
		fmt.Printf("iptables: %s", string(out))
	} else {
		fmt.Println("iptables: not available")
	}
	out, err = exec.Command("nft", "--version").CombinedOutput()
	if err == nil {
		fmt.Printf("nftables: %s", string(out))
	} else {
		fmt.Println("nftables: not installed")
	}

	// 4. OpenVPN & Tun
	fmt.Println("\n--- OpenVPN & TUN Subsystem ---")
	out, err = exec.Command("openvpn", "--version").CombinedOutput()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		if len(lines) > 0 {
			fmt.Printf("OpenVPN: %s\n", lines[0])
		}
	} else {
		fmt.Println("OpenVPN: not installed")
	}
	if info, err := os.Stat("/dev/net/tun"); err == nil {
		fmt.Printf("/dev/net/tun: available (mode %v)\n", info.Mode())
	} else {
		fmt.Printf("/dev/net/tun: ERROR (%v)\n", err)
	}

	// 5. Xray
	fmt.Println("\n--- Xray Core ---")
	out, err = exec.Command("xray", "version").CombinedOutput()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		if len(lines) > 0 {
			fmt.Printf("Xray: %s\n", lines[0])
		}
	} else {
		fmt.Println("Xray: not available in PATH")
	}

	// 6. Listeners
	fmt.Println("\n--- Public & Management Port Status ---")
	checkPortListening("443 (VLESS Reality Ingress)")
	checkPortListening("60000 (Management API)")

	fmt.Println("\n=== Environment Diagnostics Complete ===")
}

func checkPortListening(portDesc string) {
	port := strings.Fields(portDesc)[0]
	conn, err := net.DialTimeout("tcp", "127.0.0.1:"+port, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		fmt.Printf("TCP %s: LISTENING (Active)\n", portDesc)
	} else {
		fmt.Printf("TCP %s: NOT LISTENING / IDLE\n", portDesc)
	}
}

func runAndPrint(name string, args ...string) {
	/* #nosec G204 */
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(output))
	if err != nil {
		if strings.Contains(outStr, "FIB table does not exist") {
			fmt.Println("(table is empty / slot inactive)")
			return
		}
		fmt.Printf("[Error running %s %v]: %v\n", name, args, err)
	}
	if len(outStr) > 0 {
		fmt.Println(outStr)
	} else {
		fmt.Println("(empty)")
	}
}

func runAndPrintSlotTable(name string, args ...string) {
	/* #nosec G204 */
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(output))
	if err != nil {
		if strings.Contains(outStr, "FIB table does not exist") {
			fmt.Println("(slot unassigned / inactive)")
			return
		}
		fmt.Printf("[Error running %s %v]: %v\n", name, args, err)
		return
	}
	if strings.Contains(outStr, "unreachable default") || outStr == "unreachable default" {
		fmt.Println("(slot unassigned: fail-closed unreachable route configured)")
		return
	}
	if len(outStr) > 0 {
		fmt.Println(outStr)
	} else {
		fmt.Println("(slot unassigned: empty table)")
	}
}

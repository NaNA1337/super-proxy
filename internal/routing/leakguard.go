package routing

import (
	"log"
)

// EnableDNSLeakProtection prevents DNS queries from leaking outside VPN tunnels.
// It blocks all outgoing DNS (UDP/TCP 53) on non-tun interfaces.
func EnableDNSLeakProtection() error {
	_, physIface, err := GetDefaultGateway()
	if err != nil {
		return err
	}

	// Block DNS on physical interface (allow on tun+ interfaces)
	if err := runCmd("iptables", "-A", "OUTPUT", "-o", physIface, "-p", "udp", "--dport", "53", "-j", "DROP"); err != nil {
		log.Printf("[LeakGuard] Warning: failed to add DNS UDP leak rule: %v", err)
	}
	if err := runCmd("iptables", "-A", "OUTPUT", "-o", physIface, "-p", "tcp", "--dport", "53", "-j", "DROP"); err != nil {
		log.Printf("[LeakGuard] Warning: failed to add DNS TCP leak rule: %v", err)
	}

	log.Printf("[LeakGuard] DNS leak protection enabled on interface %s", physIface)
	return nil
}

// DisableDNSLeakProtection removes the DNS leak prevention rules.
func DisableDNSLeakProtection() {
	_, physIface, err := GetDefaultGateway()
	if err != nil {
		log.Printf("[LeakGuard] Warning: could not determine physical interface for DNS cleanup: %v", err)
		return
	}

	runCmd("iptables", "-D", "OUTPUT", "-o", physIface, "-p", "udp", "--dport", "53", "-j", "DROP")
	runCmd("iptables", "-D", "OUTPUT", "-o", physIface, "-p", "tcp", "--dport", "53", "-j", "DROP")
	log.Println("[LeakGuard] DNS leak protection disabled")
}

// EnableIPv6LeakProtection blocks all IPv6 traffic on the physical interface
// to prevent IPv6 leaks that bypass the IPv4 VPN tunnels.
func EnableIPv6LeakProtection() error {
	_, physIface, err := GetDefaultGateway()
	if err != nil {
		return err
	}

	// Block all outgoing IPv6 on physical interface
	if err := runCmd("ip6tables", "-A", "OUTPUT", "-o", physIface, "-j", "DROP"); err != nil {
		log.Printf("[LeakGuard] Warning: failed to add IPv6 leak rule: %v", err)
	}
	// Block all incoming IPv6 on physical interface
	if err := runCmd("ip6tables", "-A", "INPUT", "-i", physIface, "-j", "DROP"); err != nil {
		log.Printf("[LeakGuard] Warning: failed to add IPv6 input leak rule: %v", err)
	}

	log.Printf("[LeakGuard] IPv6 leak protection enabled on interface %s", physIface)
	return nil
}

// DisableIPv6LeakProtection removes the IPv6 leak prevention rules.
func DisableIPv6LeakProtection() {
	_, physIface, err := GetDefaultGateway()
	if err != nil {
		log.Printf("[LeakGuard] Warning: could not determine physical interface for IPv6 cleanup: %v", err)
		return
	}

	runCmd("ip6tables", "-D", "OUTPUT", "-o", physIface, "-j", "DROP")
	runCmd("ip6tables", "-D", "INPUT", "-i", physIface, "-j", "DROP")
	log.Println("[LeakGuard] IPv6 leak protection disabled")
}

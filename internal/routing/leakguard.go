package routing

import (
	"log"
)

// EnableDNSLeakProtection prevents DNS queries from leaking outside VPN tunnels.
// It allows root management traffic (for discovery and reputation checks) on the physical
// interface, while strictly blocking all non-root and marked proxy DNS traffic.
func EnableDNSLeakProtection() error {
	_, physIface, err := GetDefaultGateway()
	if err != nil {
		return err
	}

	// 1. Allow root management daemon to resolve discovery and reputation APIs
	if runCmd("iptables", "-C", "OUTPUT", "-o", physIface, "-m", "owner", "--uid-owner", "0", "-p", "udp", "--dport", "53", "-j", "ACCEPT") != nil {
		_ = runCmd("iptables", "-A", "OUTPUT", "-o", physIface, "-m", "owner", "--uid-owner", "0", "-p", "udp", "--dport", "53", "-j", "ACCEPT")
	}
	if runCmd("iptables", "-C", "OUTPUT", "-o", physIface, "-m", "owner", "--uid-owner", "0", "-p", "tcp", "--dport", "53", "-j", "ACCEPT") != nil {
		_ = runCmd("iptables", "-A", "OUTPUT", "-o", physIface, "-m", "owner", "--uid-owner", "0", "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
	}

	// 2. Block all other DNS on physical interface (strictly enforced for proxy clients / non-root)
	if runCmd("iptables", "-C", "OUTPUT", "-o", physIface, "-p", "udp", "--dport", "53", "-j", "DROP") != nil {
		_ = runCmd("iptables", "-A", "OUTPUT", "-o", physIface, "-p", "udp", "--dport", "53", "-j", "DROP")
	}
	if runCmd("iptables", "-C", "OUTPUT", "-o", physIface, "-p", "tcp", "--dport", "53", "-j", "DROP") != nil {
		_ = runCmd("iptables", "-A", "OUTPUT", "-o", physIface, "-p", "tcp", "--dport", "53", "-j", "DROP")
	}

	log.Printf("[LeakGuard] DNS leak protection enabled on interface %s (daemon exempted, proxy blocked)", physIface)
	return nil
}

// DisableDNSLeakProtection removes the DNS leak prevention rules.
func DisableDNSLeakProtection() {
	_, physIface, err := GetDefaultGateway()
	if err != nil {
		log.Printf("[LeakGuard] Warning: could not determine physical interface for DNS cleanup: %v", err)
		return
	}

	for runCmd("iptables", "-D", "OUTPUT", "-o", physIface, "-m", "owner", "--uid-owner", "0", "-p", "udp", "--dport", "53", "-j", "ACCEPT") == nil {
	}
	for runCmd("iptables", "-D", "OUTPUT", "-o", physIface, "-m", "owner", "--uid-owner", "0", "-p", "tcp", "--dport", "53", "-j", "ACCEPT") == nil {
	}
	for runCmd("iptables", "-D", "OUTPUT", "-o", physIface, "-p", "udp", "--dport", "53", "-j", "DROP") == nil {
	}
	for runCmd("iptables", "-D", "OUTPUT", "-o", physIface, "-p", "tcp", "--dport", "53", "-j", "DROP") == nil {
	}
	log.Println("[LeakGuard] DNS leak protection disabled")
}

// EnableIPv6LeakProtection blocks all IPv6 traffic on the physical interface
// to prevent IPv6 leaks that bypass the IPv4 VPN tunnels.
func EnableIPv6LeakProtection() error {
	_, physIface, err := GetDefaultGateway()
	if err != nil {
		return err
	}

	if runCmd("ip6tables", "-C", "OUTPUT", "-o", physIface, "-j", "DROP") != nil {
		_ = runCmd("ip6tables", "-A", "OUTPUT", "-o", physIface, "-j", "DROP")
	}
	if runCmd("ip6tables", "-C", "INPUT", "-i", physIface, "-j", "DROP") != nil {
		_ = runCmd("ip6tables", "-A", "INPUT", "-i", physIface, "-j", "DROP")
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

	for runCmd("ip6tables", "-D", "OUTPUT", "-o", physIface, "-j", "DROP") == nil {
	}
	for runCmd("ip6tables", "-D", "INPUT", "-i", physIface, "-j", "DROP") == nil {
	}
	log.Println("[LeakGuard] IPv6 leak protection disabled")
}

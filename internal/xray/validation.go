package xray

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

const (
	VlessPublicPort = 443
	ManagementPort  = 60000

	DefaultVlessPublicPort = VlessPublicPort
	DefaultRealityTarget   = "www.microsoft.com:443"
	DefaultRealitySNI      = "www.microsoft.com"
	DefaultRealityFP       = "chrome"
	DefaultFlow            = "xtls-rprx-vision"
	DefaultSecurity        = "reality"
)

var (
	hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
)

// ValidateVlessPublicPort enforces that VLESS Reality public ingress is strictly fixed to TCP/443.
// All other ports (including 80, 1080, 8080, 60000, 60001) are forbidden as VLESS client entry points.
func ValidateVlessPublicPort(port int) error {
	if port != VlessPublicPort {
		return fmt.Errorf("invalid VLESS public ingress port %d: must be strictly %d (TCP/443)", port, VlessPublicPort)
	}
	return nil
}

// ValidateManagementPort enforces that Web Manager and Management API listen strictly on TCP 60000.
// Port 443 is strictly forbidden for management access.
func ValidateManagementPort(port int) error {
	if port != ManagementPort {
		return fmt.Errorf("invalid management port %d: must be strictly %d (TCP/60000)", port, ManagementPort)
	}
	return nil
}

// ValidatePublicPort is an alias for ValidateVlessPublicPort for backward compatibility.
func ValidatePublicPort(port int) error {
	return ValidateVlessPublicPort(port)
}

// ValidatePublicAddress enforces that the public endpoint address is a valid public domain or non-loopback IP.
// Strictly rejects localhost, 127.0.0.1, 0.0.0.0, ::, ::1, and loopback ranges.
func ValidatePublicAddress(addr string) error {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return fmt.Errorf("public endpoint address cannot be empty")
	}

	// Reject URL schemes, ports, paths
	if strings.Contains(trimmed, "://") || strings.Contains(trimmed, "/") || strings.Contains(trimmed, ":") && !strings.Contains(trimmed, "[") && strings.Count(trimmed, ":") == 1 {
		return fmt.Errorf("public endpoint address %q must be a pure host/domain (no scheme, path, or port)", addr)
	}

	// Reject localhost keyword
	if strings.EqualFold(trimmed, "localhost") {
		return fmt.Errorf("public endpoint address cannot be localhost")
	}

	// Check if it is an IP address
	cleanIP := strings.Trim(trimmed, "[]")
	if ip := net.ParseIP(cleanIP); ip != nil {
		if ip.IsLoopback() {
			return fmt.Errorf("public endpoint address %q cannot be a loopback IP", addr)
		}
		if ip.IsUnspecified() {
			return fmt.Errorf("public endpoint address %q cannot be an unspecified IP (0.0.0.0 / ::)", addr)
		}
		return nil
	}

	// Hostname validation
	if len(trimmed) > 253 || !hostnameRegex.MatchString(trimmed) {
		return fmt.Errorf("public endpoint address %q is not a valid hostname or IP address", addr)
	}

	return nil
}

// ValidateRealitySNI enforces production validation for Reality SNI server names:
// - Non-empty
// - Valid RFC 1123 hostname
// - Cannot be localhost
// - Cannot be an IP address (IPv4 or IPv6)
// - Cannot contain scheme (http://, https://)
// - Cannot contain path (/...)
// - Cannot contain port (:443, etc.)
func ValidateRealitySNI(sni string) error {
	trimmed := strings.TrimSpace(sni)
	if trimmed == "" {
		return fmt.Errorf("SNI cannot be empty")
	}

	// Reject schemes, paths, ports, credentials
	if strings.Contains(trimmed, "://") || strings.HasPrefix(trimmed, "/") {
		return fmt.Errorf("SNI %q cannot contain URL scheme or path", sni)
	}
	if strings.ContainsAny(trimmed, ":/?#@ ") {
		return fmt.Errorf("SNI %q contains invalid characters or port delimiter", sni)
	}

	// Reject localhost
	if strings.EqualFold(trimmed, "localhost") {
		return fmt.Errorf("SNI cannot be localhost")
	}

	// Reject IP addresses (IPv4 or IPv6)
	if net.ParseIP(trimmed) != nil {
		return fmt.Errorf("SNI %q cannot be an IP address", sni)
	}

	// Hostname length
	if len(trimmed) > 253 {
		return fmt.Errorf("SNI %q exceeds maximum hostname length of 253 characters", sni)
	}

	// Must be a valid hostname
	if !hostnameRegex.MatchString(trimmed) {
		return fmt.Errorf("SNI %q is not a valid RFC 1123 hostname", sni)
	}

	return nil
}

// ValidateRealityDestination validates that the Reality camouflage destination:
// - Uses port 443 (fixed requirement for camouflage target)
// - Hostname matches expected SNI (if provided)
// - Hostname is a valid SNI
func ValidateRealityDestination(dest string, expectedSNI string) (string, int, error) {
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return "", 0, fmt.Errorf("reality destination cannot be empty")
	}

	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return "", 0, fmt.Errorf("invalid reality destination %q: must be in host:port format: %w", dest, err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid reality destination port %q: %w", portStr, err)
	}

	if port != 443 {
		return "", 0, fmt.Errorf("invalid reality destination port %d: camouflage destination port must be exactly 443", port)
	}

	if err := ValidateRealitySNI(host); err != nil {
		return "", 0, fmt.Errorf("invalid reality destination host %q: %w", host, err)
	}

	if expectedSNI != "" && !strings.EqualFold(host, expectedSNI) {
		return "", 0, fmt.Errorf("reality destination host %q must match SNI %q", host, expectedSNI)
	}

	return host, port, nil
}

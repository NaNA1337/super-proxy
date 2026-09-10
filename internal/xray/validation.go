package xray

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

const (
	MinPublicPort = 60000
	MaxPublicPort = 61000

	DefaultVlessPublicPort = 60001
	DefaultRealityTarget   = "www.microsoft.com:443"
	DefaultRealitySNI      = "www.microsoft.com"
	DefaultRealityFP       = "chrome"
	DefaultFlow            = "xtls-rprx-vision"
	DefaultSecurity        = "reality"
)

var (
	hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
)

// ValidatePublicPort enforces production public port restrictions (60000-61000).
// Ports outside this range (including 443, 80, 1080, 8080) are strictly forbidden
// as client public entry points.
func ValidatePublicPort(port int) error {
	if port < MinPublicPort || port > MaxPublicPort {
		return fmt.Errorf("invalid public port %d: must be strictly within range [%d, %d]", port, MinPublicPort, MaxPublicPort)
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

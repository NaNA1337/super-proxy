package openvpn

import (
	"context"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// OpenVPNVersion holds parsed version info
type OpenVPNVersion struct {
	Major int
	Minor int
	Patch int
	Raw   string
}

// DetectOpenVPNVersion returns the installed OpenVPN version
func DetectOpenVPNVersion(ctx context.Context) *OpenVPNVersion {
	/* #nosec G204 */
	cmd := exec.CommandContext(ctx, "openvpn", "--version")
	output, _ := cmd.CombinedOutput()
	// openvpn --version outputs to stderr and exits with code 1
	// First line is like: "OpenVPN 2.5.9 x86_64..."
	lines := strings.Split(string(output), "\n")
	if len(lines) == 0 {
		return nil
	}

	re := regexp.MustCompile(`OpenVPN\s+(\d+)\.(\d+)\.(\d+)`)
	matches := re.FindStringSubmatch(lines[0])
	if len(matches) < 4 {
		return nil
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch, _ := strconv.Atoi(matches[3])

	return &OpenVPNVersion{
		Major: major,
		Minor: minor,
		Patch: patch,
		Raw:   lines[0],
	}
}

// SupportsDisableDCO returns true if the OpenVPN version supports the --disable-dco flag
// This is only available in OpenVPN 2.6+ and 3.x
func (v *OpenVPNVersion) SupportsDisableDCO() bool {
	if v == nil {
		return false
	}
	if v.Major >= 3 {
		return true
	}
	return v.Major == 2 && v.Minor >= 6
}

// DetectDCOCapability checks if the host supports OpenVPN DCO and if the config is compatible.
// Returns (dcoCapable, supportsDisableDCOFlag).
func DetectDCOCapability(ctx context.Context, cfgStr string) bool {
	// 1. Check OpenVPN version — only 2.6+ supports DCO at all
	version := DetectOpenVPNVersion(ctx)
	if version == nil {
		log.Printf("[DCO] Could not detect OpenVPN version")
		return false
	}
	log.Printf("[DCO] Detected %s", version.Raw)

	if !version.SupportsDisableDCO() {
		log.Printf("[DCO] OpenVPN %d.%d.%d does not support DCO (requires 2.6+)", version.Major, version.Minor, version.Patch)
		return false
	}

	// 2. Check if ovpn_dco kernel module is loaded
	/* #nosec G204 */
	cmd := exec.CommandContext(ctx, "lsmod")
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "ovpn_dco") {
		log.Printf("[DCO] ovpn_dco kernel module not found or lsmod failed")
		return false
	}

	// 3. Check config compatibility
	// DCO currently does not support certain ciphers like AES-128-CBC well in some environments,
	// or it strictly requires AES-256-GCM / CHACHA20-POLY1305.
	// For safety, if config forces CBC, we disable DCO.
	if strings.Contains(cfgStr, "cipher AES-128-CBC") || strings.Contains(cfgStr, "cipher AES-256-CBC") {
		log.Printf("[DCO] Config contains CBC cipher, which may be incompatible with DCO. Disabling DCO.")
		return false
	}

	log.Printf("[DCO] Host and config appear compatible with Data Channel Offload.")
	return true
}

// GetDCOArgs returns the OpenVPN arguments needed based on DCO detection results.
// For OpenVPN 2.5 and below, no DCO-related args are returned (the flag doesn't exist).
// For 2.6+, returns --disable-dco if DCO is not available.
func GetDCOArgs(ctx context.Context, cfgStr string) []string {
	version := DetectOpenVPNVersion(ctx)
	if version == nil || !version.SupportsDisableDCO() {
		// Old OpenVPN — no DCO flags at all
		return nil
	}

	if !DetectDCOCapability(ctx, cfgStr) {
		return []string{"--disable-dco"}
	}

	// DCO is available and config is compatible — don't add --disable-dco
	// (2.6+ enables DCO by default when ovpn_dco is present)
	return nil
}

package openvpn

import (
	"context"
	"log"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type DCOStatus string

const (
	DCOStatusSupported   DCOStatus = "DCO_SUPPORTED"
	DCOStatusRequested   DCOStatus = "DCO_STATUS=REQUESTED"
	DCOStatusActive      DCOStatus = "DCO_STATUS=ACTIVE"
	DCOStatusFallback    DCOStatus = "DCO_STATUS=FALLBACK"
	DCOStatusFailed      DCOStatus = "DCO_STATUS=FAILED"
	DCOStatusUnavailable DCOStatus = "DCO_STATUS=UNAVAILABLE"
	DCOStatusDisabled    DCOStatus = "DCO_STATUS=DISABLED"
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
func DetectDCOCapability(ctx context.Context, cfgStr string) bool {
	// 1. Check OpenVPN version — only 2.6+ supports DCO at all
	version := DetectOpenVPNVersion(ctx)
	if version == nil {
		log.Printf("[DCO] Could not detect OpenVPN version")
		return false
	}

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
	if strings.Contains(cfgStr, "cipher AES-128-CBC") || strings.Contains(cfgStr, "cipher AES-256-CBC") {
		log.Printf("[DCO] Config contains CBC cipher, which may be incompatible with DCO. Disabling DCO.")
		return false
	}

	log.Printf("[DCO] Host and config appear compatible with Data Channel Offload.")
	return true
}

// GetDCOArgs returns the OpenVPN arguments needed based on DCO detection results.
func GetDCOArgs(ctx context.Context, cfgStr string) []string {
	version := DetectOpenVPNVersion(ctx)
	if version == nil || !version.SupportsDisableDCO() {
		return nil
	}

	if !DetectDCOCapability(ctx, cfgStr) {
		return []string{"--disable-dco"}
	}

	return nil
}

// ParseDCOLogLine scans an OpenVPN runtime output line to determine runtime DCO state.
func ParseDCOLogLine(line string) DCOStatus {
	lineLower := strings.ToLower(line)
	if strings.Contains(lineLower, "cannot open") || strings.Contains(lineLower, "dco failed") || strings.Contains(lineLower, "dco error") {
		return DCOStatusFailed
	}
	if strings.Contains(lineLower, "falling back to userspace") || strings.Contains(lineLower, "fallback to tun") || strings.Contains(lineLower, "falling back to standard") {
		return DCOStatusFallback
	}
	if strings.Contains(lineLower, "--disable-dco is present") || strings.Contains(lineLower, "dco disabled") || strings.Contains(lineLower, "dco is disabled") {
		return DCOStatusDisabled
	}
	if strings.Contains(lineLower, "using dco") || strings.Contains(lineLower, "dco device opened") || strings.Contains(lineLower, "dco device ovpn") {
		return DCOStatusActive
	}
	return ""
}

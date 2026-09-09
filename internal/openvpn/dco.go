package openvpn

import (
	"context"
	"log"
	"os/exec"
	"strings"
)

// DetectDCOCapability checks if the host supports OpenVPN DCO and if the config is compatible
func DetectDCOCapability(ctx context.Context, cfgStr string) bool {
	// 1. Check if ovpn_dco kernel module is loaded
	/* #nosec G204 */
	cmd := exec.CommandContext(ctx, "lsmod")
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "ovpn_dco") {
		log.Printf("[DCO] ovpn_dco kernel module not found or lsmod failed")
		return false
	}

	// 2. Check config compatibility
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

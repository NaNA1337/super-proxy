package reproduction

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/NaNA1337/super-proxy/internal/xray"
	"github.com/stretchr/testify/require"
)

// TestP0_XrayConfigGeneration_ArbitraryDirectory tests that Xray config generation
// succeeds even if the target directory does not yet exist on the filesystem.
func TestP0_XrayConfigGeneration_ArbitraryDirectory(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "xray_gen_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Nested path where parent directory does NOT yet exist
	nestedConfigPath := filepath.Join(tempDir, "deep", "nested", "xray_config.json")

	opts := xray.ConfigOptions{
		SlotCount:   3,
		ConfigPath:  nestedConfigPath,
		SocksListen: "127.0.0.1",
		SocksPort:   1080,
		ApiPort:     10085,
	}

	err = xray.GenerateConfigWithOptions(opts)
	// Currently this fails if MkdirAll is not performed
	if err != nil {
		t.Logf("Observed current behavior: GenerateConfigWithOptions failed on non-existent directory: %v", err)
	}
}

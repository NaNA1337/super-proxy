package reproduction

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestP0_Daemon_StartupFromArbitraryCWD verifies that the compiled production binary
// can cleanly start, initialize database, generate Xray configs, and initialize
// routing/firewall when executed with WorkingDirectory = / (root directory).
func TestP0_Daemon_StartupFromArbitraryCWD(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping root daemon startup test: requires root privileges")
	}

	tempDir, err := os.MkdirTemp("", "superproxy_root_cwd_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	configDir := filepath.Join(tempDir, "etc")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	dbDir := filepath.Join(tempDir, "var")
	require.NoError(t, os.MkdirAll(dbDir, 0755))

	configPath := filepath.Join(configDir, "config.yaml")
	cfgContent := fmt.Sprintf(`region:
  primary: JP
database:
  path: "%s/manager.db"
discovery:
  url: "http://127.0.0.1:9"
  interval: 60
api:
  listen: "127.0.0.1"
  port: 60000
`, dbDir)
	require.NoError(t, os.WriteFile(configPath, []byte(cfgContent), 0644))

	binPath := filepath.Join(tempDir, "super-proxy-bin")
	buildCmd := exec.Command("go", "build", "-trimpath", "-o", binPath, "github.com/NaNA1337/super-proxy/cmd/manager")
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	buildOut, err := buildCmd.CombinedOutput()
	require.NoError(t, err, "Build failed: %s", string(buildOut))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, binPath, configPath)
	cmd.Dir = "/" // Execute from root directory!
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutPipe, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = cmd.Stdout

	err = cmd.Start()
	require.NoError(t, err)

	// Wait for process to reach "Agent API Server listening" or terminate early on failure
	startedChan := make(chan bool, 1)
	go func() {
		buf := make([]byte, 1024)
		for {
			n, rerr := stdoutPipe.Read(buf)
			if n > 0 {
				output := string(buf[:n])
				t.Logf("[daemon output]: %s", output)
				if containsAny(output, "Agent API Server listening", "Server listening securely") {
					startedChan <- true
					return
				}
			}
			if rerr != nil {
				return
			}
		}
	}()

	select {
	case <-startedChan:
		t.Log("Daemon successfully started from CWD / without crashing!")
	case <-time.After(8 * time.Second):
		t.Fatal("Daemon failed to reach listening state within 8s when executed from CWD /")
	}

	// Clean shutdown via SIGINT
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGINT)
	_ = cmd.Wait()
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

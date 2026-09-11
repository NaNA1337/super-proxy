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

// Run the real daemon in its own network namespace: its firewall and fixed
// ports must never collide with a running installation on the development host.
func TestP0_Daemon_StartupFromArbitraryCWD(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root and network namespaces")
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(fmt.Sprintf(`region:
  primary: JP
database:
  path: %s/manager.db
discovery:
  url: http://127.0.0.1:9
  interval: 60
api:
  listen: 127.0.0.1
  port: 60000
  key: isolated-startup-test
`, dir)), 0600))
	binPath := filepath.Join(dir, "super-proxy")
	build := exec.Command("go", "build", "-trimpath", "-o", binPath, "github.com/NaNA1337/super-proxy/cmd/manager")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := build.CombinedOutput()
	require.NoError(t, err, "%s", out)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "--net", "--mount", "bash", "-c", `
set -eu
mount -t tmpfs tmpfs /run
ip link set lo up
"$1" "$2" > "$3" 2>&1 &
daemon_pid=$!
trap 'kill -TERM "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" || true' EXIT
for i in $(seq 1 100); do
 if curl --silent --fail --insecure -H 'Authorization: Bearer isolated-startup-test' https://127.0.0.1:60000/api/v1/status > /dev/null; then exit 0; fi
 sleep 0.1
done
cat "$3"
exit 1
`, "startup-test", binPath, cfgPath, filepath.Join(dir, "daemon.log"))
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, "startup from / did not serve authenticated HTTPS: %s", out)
	require.FileExists(t, filepath.Join(dir, "cert.pem"))
	require.FileExists(t, filepath.Join(dir, "key.pem"))
}

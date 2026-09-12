package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDaemonPIDRunning(t *testing.T) {
	pidPath := filepath.Join(t.TempDir(), "super-proxy.pid")
	require.NoError(t, os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0600))
	running, err := daemonPIDRunning(pidPath)
	require.NoError(t, err)
	require.True(t, running)

	require.NoError(t, os.WriteFile(pidPath, []byte("invalid"), 0600))
	running, err = daemonPIDRunning(pidPath)
	require.NoError(t, err)
	require.False(t, running)
}

func TestDatabaseCleanRequiresExplicitConfirmation(t *testing.T) {
	err := runDatabaseCommand([]string{"clean"})
	require.ErrorContains(t, err, "refusing to clean without -yes")
}

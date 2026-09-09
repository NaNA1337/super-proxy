package openvpn

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/routing"
)

type Tunnel struct {
	ID                string
	SlotIndex         int
	Interface         string
	Node              *models.Node
	Cmd               *exec.Cmd
	Cancel            context.CancelFunc
	Mu                sync.Mutex
	State             string
	DrainingStartedAt time.Time
	tmpConfigPath     string
	cleanupOnce       sync.Once
}

// StartTunnel decodes config, injects route-nopull, and starts the OpenVPN process
func StartTunnel(ctx context.Context, slotIndex int, node *models.Node) (*Tunnel, error) {
	// 1. Decode config
	configData, err := base64.StdEncoding.DecodeString(node.OpenVPN)
	if err != nil {
		return nil, fmt.Errorf("failed to decode openvpn config: %w", err)
	}
	cfgStr := string(configData)

	// 2. Inject route-nopull to prevent overwriting main routing table
	if !strings.Contains(cfgStr, "route-nopull") {
		cfgStr += "\nroute-nopull\n"
	}

	// 3. Write to temp file
	tmpFile, err := os.CreateTemp("", fmt.Sprintf("ovpn_slot%d_*.conf", slotIndex))
	if err != nil {
		return nil, fmt.Errorf("failed to create temp config file: %w", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(cfgStr); err != nil {
		return nil, err
	}

	interfaceName := fmt.Sprintf("tun%d", slotIndex)

	ctxChild, cancel := context.WithCancel(ctx)

	// 4. Prevent routing recursion (P0-5) — MUST succeed before starting OpenVPN
	if err := routing.AddEndpointBypassRule(node.IP); err != nil {
		cancel()
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("FATAL: failed to add endpoint bypass rule for %s, refusing to start tunnel to prevent routing recursion: %w", node.IP, err)
	}

	// 5. Build OpenVPN arguments
	args := []string{
		"--config", tmpFile.Name(),
		"--dev", interfaceName,
		"--auth-nocache",
		"--script-security", "2",
	}

	// Version-aware DCO handling
	dcoArgs := GetDCOArgs(ctxChild, cfgStr)
	args = append(args, dcoArgs...)

	/* #nosec G204 */
	cmd := exec.CommandContext(ctxChild, "openvpn", args...)

	// Capture stdout/stderr for logging
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Printf("[Slot %d] Starting OpenVPN for Node %s on %s", slotIndex, node.IP, interfaceName)
	if err := cmd.Start(); err != nil {
		cancel()
		routing.RemoveEndpointBypassRule(node.IP)
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to start openvpn: %w", err)
	}

	tunnel := &Tunnel{
		ID:            fmt.Sprintf("slot-%d", slotIndex),
		SlotIndex:     slotIndex,
		Interface:     interfaceName,
		Node:          node,
		Cmd:           cmd,
		Cancel:        cancel,
		State:         "ACTIVE",
		tmpConfigPath: tmpFile.Name(),
	}

	// Wait for process in background
	go func() {
		err := cmd.Wait()
		tunnel.Mu.Lock()
		tunnel.State = "FAILED"
		tunnel.Mu.Unlock()
		if err != nil {
			log.Printf("[Slot %d] OpenVPN process exited: %v", slotIndex, err)
		} else {
			log.Printf("[Slot %d] OpenVPN process exited gracefully", slotIndex)
		}
		// Run cleanup exactly once (coordinated with Stop())
		tunnel.cleanup()
	}()

	// Wait a bit to ensure it doesn't immediately crash
	time.Sleep(2 * time.Second)
	tunnel.Mu.Lock()
	active := tunnel.State == "ACTIVE"
	tunnel.Mu.Unlock()

	if !active {
		cancel()
		return nil, fmt.Errorf("openvpn process exited immediately")
	}

	return tunnel, nil
}

// cleanup removes temporary files and endpoint bypass rules. Safe to call multiple times.
func (t *Tunnel) cleanup() {
	t.cleanupOnce.Do(func() {
		os.Remove(t.tmpConfigPath)
		if err := routing.RemoveEndpointBypassRule(t.Node.IP); err != nil {
			log.Printf("[Slot %d] Warning: failed to remove endpoint bypass rule for %s: %v", t.SlotIndex, t.Node.IP, err)
		}
		log.Printf("[Slot %d] Cleanup completed for tunnel to %s", t.SlotIndex, t.Node.IP)
	})
}

// Stop terminates the OpenVPN process and waits for cleanup to complete.
func (t *Tunnel) Stop() {
	if t.Cancel != nil {
		t.Cancel()
	}
	// Wait for the process to actually exit (with a timeout)
	done := make(chan struct{})
	go func() {
		if t.Cmd != nil && t.Cmd.Process != nil {
			t.Cmd.Wait() //nolint:errcheck // already handled in goroutine
		}
		close(done)
	}()

	select {
	case <-done:
		// Process exited cleanly
	case <-time.After(10 * time.Second):
		log.Printf("[Slot %d] Warning: OpenVPN process did not exit within 10s after cancel, force killing", t.SlotIndex)
		if t.Cmd != nil && t.Cmd.Process != nil {
			t.Cmd.Process.Kill() //nolint:errcheck
		}
	}

	// Ensure cleanup runs even if the background goroutine hasn't run yet
	t.cleanup()
}

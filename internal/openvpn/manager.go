package openvpn

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/NaNA1337/super-proxy/internal/discovery"
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
	DCOStatus         DCOStatus
	DrainingStartedAt time.Time
	tmpConfigPath     string
	cleanupOnce       sync.Once

	// Lifecycle synchronization: single waiter goroutine owns cmd.Wait()
	doneChan          chan struct{}
	exitErr           error
}

// StartTunnel decodes config, injects route-nopull, and starts the OpenVPN process
func StartTunnel(ctx context.Context, slotIndex int, node *models.Node) (*Tunnel, error) {
	// 1. Validate untrusted config and generate safe canonical local config
	safeConfigStr, _, err := discovery.ParseOpenVPNConfig(node.OpenVPN)
	if err != nil {
		return nil, fmt.Errorf("failed to validate untrusted openvpn config: %w", err)
	}

	// 2. Write strictly validated safe config to temp file (safeConfigStr already includes route-nopull)
	tmpFile, err := os.CreateTemp("", fmt.Sprintf("ovpn_slot%d_*.conf", slotIndex))
	if err != nil {
		return nil, fmt.Errorf("failed to create temp config file: %w", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(safeConfigStr); err != nil {
		return nil, err
	}

	interfaceName := fmt.Sprintf("tun%d", slotIndex)

	ctxChild, cancel := context.WithCancel(ctx)

	// 3. Prevent routing recursion (P0-5) — MUST succeed before starting OpenVPN
	if err := routing.AddEndpointBypassRule(node.IP); err != nil {
		cancel()
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("FATAL: failed to add endpoint bypass rule for %s, refusing to start tunnel to prevent routing recursion: %w", node.IP, err)
	}

	// 4. Build OpenVPN arguments (script execution completely disabled, NO --script-security)
	args := []string{
		"--config", tmpFile.Name(),
		"--dev", interfaceName,
		"--auth-nocache",
	}

	// Version-aware DCO handling
	dcoArgs := GetDCOArgs(ctxChild, safeConfigStr)
	args = append(args, dcoArgs...)

	/* #nosec G204 */
	cmd := exec.CommandContext(ctxChild, "openvpn", args...)
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return cmd.Process.Signal(syscall.SIGTERM)
		}
		return nil
	}

	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()

	log.Printf("[Slot %d] Starting OpenVPN for Node %s on %s", slotIndex, node.IP, interfaceName)
	if err := cmd.Start(); err != nil {
		cancel()
		routing.RemoveEndpointBypassRule(node.IP)
		os.Remove(tmpFile.Name())
		return nil, fmt.Errorf("failed to start openvpn: %w", err)
	}

	initialDCO := DCOStatusRequested
	for _, arg := range args {
		if arg == "--disable-dco" {
			initialDCO = DCOStatusDisabled
			break
		}
	}

	tunnel := &Tunnel{
		ID:            fmt.Sprintf("slot-%d", slotIndex),
		SlotIndex:     slotIndex,
		Interface:     interfaceName,
		Node:          node,
		Cmd:           cmd,
		Cancel:        cancel,
		State:         "ACTIVE",
		DCOStatus:     initialDCO,
		tmpConfigPath: tmpFile.Name(),
		doneChan:      make(chan struct{}),
	}

	scanLog := func(r io.Reader) {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Text()
			if status := ParseDCOLogLine(line); status != "" {
				tunnel.Mu.Lock()
				tunnel.DCOStatus = status
				tunnel.Mu.Unlock()
				log.Printf("[Slot %d] OpenVPN runtime DCO status confirmed: %s", slotIndex, status)
			}
		}
		if err := scanner.Err(); err != nil && err != io.EOF {
			log.Printf("[Slot %d] Log scanner encountered error: %v", slotIndex, err)
		}
	}
	if stdoutPipe != nil {
		go scanLog(stdoutPipe)
	}
	if stderrPipe != nil {
		go scanLog(stderrPipe)
	}

	// Sole waiter goroutine: exclusive owner of cmd.Wait()
	go func() {
		defer close(tunnel.doneChan)
		err := cmd.Wait()
		tunnel.Mu.Lock()
		tunnel.exitErr = err
		tunnel.State = "FAILED"
		tunnel.Mu.Unlock()
		if err != nil {
			log.Printf("[Slot %d] OpenVPN process exited: %v", slotIndex, err)
		} else {
			log.Printf("[Slot %d] OpenVPN process exited gracefully", slotIndex)
		}
		// Run cleanup exactly once
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
		if t.tmpConfigPath != "" {
			_ = os.Remove(t.tmpConfigPath)
		}
		if t.Node != nil && t.Node.IP != "" {
			if err := routing.RemoveEndpointBypassRule(t.Node.IP); err != nil {
				log.Printf("[Slot %d] Warning: failed to remove endpoint bypass rule for %s: %v", t.SlotIndex, t.Node.IP, err)
			}
			log.Printf("[Slot %d] Cleanup completed for tunnel to %s", t.SlotIndex, t.Node.IP)
		}
	})
}

// Stop terminates the OpenVPN process and waits for cleanup to complete.
// Strictly adheres to the single-waiter lifecycle contract (never calls cmd.Wait()).
func (t *Tunnel) Stop() {
	if t.Cancel != nil {
		t.Cancel()
	}

	if t.doneChan != nil {
		select {
		case <-t.doneChan:
			// Process exited cleanly via context cancellation
		case <-time.After(5 * time.Second):
			log.Printf("[Slot %d] Warning: OpenVPN process did not exit within 5s after cancel, force killing (SIGKILL)", t.SlotIndex)
			if t.Cmd != nil && t.Cmd.Process != nil {
				_ = t.Cmd.Process.Kill()
			}
			select {
			case <-t.doneChan:
				log.Printf("[Slot %d] OpenVPN process exited after SIGKILL", t.SlotIndex)
			case <-time.After(5 * time.Second):
				log.Printf("[Slot %d] Error: OpenVPN process could not be reaped after SIGKILL", t.SlotIndex)
			}
		}
	}

	// Ensure cleanup has run
	t.cleanup()
}

// Done returns a channel that is closed when the OpenVPN process exits.
func (t *Tunnel) Done() <-chan struct{} {
	return t.doneChan
}

// ExitError returns the error from cmd.Wait() after Done() is closed.
func (t *Tunnel) ExitError() error {
	t.Mu.Lock()
	defer t.Mu.Unlock()
	return t.exitErr
}

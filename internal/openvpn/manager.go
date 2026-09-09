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
)

type Tunnel struct {
	ID        string
	SlotIndex int
	Interface string
	Node      *models.Node
	Cmd       *exec.Cmd
	Cancel    context.CancelFunc
	mu        sync.Mutex
	State     string
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
	// Also ensure we don't drop privileges if we need to configure routing, or we let controller do it.
	// We will run as root for now since Controller runs as root.

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

	// 4. Start OpenVPN process
	args := []string{
		"--config", tmpFile.Name(),
		"--dev", interfaceName,
		"--auth-nocache",
		"--script-security", "2",
	}

	if !DetectDCOCapability(ctxChild, cfgStr) {
		args = append(args, "--disable-dco")
	}

	/* #nosec G204 */
	cmd := exec.CommandContext(ctxChild, "openvpn", args...)

	// We can capture stdout/stderr for logging
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Printf("[Slot %d] Starting OpenVPN for Node %s on %s", slotIndex, node.IP, interfaceName)
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start openvpn: %w", err)
	}

	tunnel := &Tunnel{
		ID:        fmt.Sprintf("slot-%d", slotIndex),
		SlotIndex: slotIndex,
		Interface: interfaceName,
		Node:      node,
		Cmd:       cmd,
		Cancel:    cancel,
		State:     "ACTIVE",
	}

	// Wait for process in background
	go func() {
		err := cmd.Wait()
		tunnel.mu.Lock()
		tunnel.State = "FAILED"
		tunnel.mu.Unlock()
		if err != nil {
			log.Printf("[Slot %d] OpenVPN process exited: %v", slotIndex, err)
		} else {
			log.Printf("[Slot %d] OpenVPN process exited gracefully", slotIndex)
		}
		// Clean up temp file
		os.Remove(tmpFile.Name())
	}()

	// Wait a bit to ensure it doesn't immediately crash
	time.Sleep(2 * time.Second)
	tunnel.mu.Lock()
	active := tunnel.State == "ACTIVE"
	tunnel.mu.Unlock()

	if !active {
		cancel()
		return nil, fmt.Errorf("openvpn process exited immediately")
	}

	return tunnel, nil
}

// Stop terminates the OpenVPN process
func (t *Tunnel) Stop() {
	if t.Cancel != nil {
		t.Cancel()
	}
}

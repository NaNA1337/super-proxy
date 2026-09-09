package scheduler

import (
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/openvpn"
	"github.com/NaNA1337/super-proxy/internal/reputation"
)

func TestConntrackErrorSemantics(t *testing.T) {
	if ConnectionCountUnknown != -1 {
		t.Errorf("expected ConnectionCountUnknown to be -1, got %d", ConnectionCountUnknown)
	}

	formatted := FormatDrainingStatus(1, ConnectionCountUnknown)
	if formatted != "Slot 1 draining: connections UNKNOWN" {
		t.Errorf("unexpected format for UNKNOWN count: %s", formatted)
	}

	formatted2 := FormatDrainingStatus(2, 5)
	if formatted2 != "Slot 2 draining: 5 active connections" {
		t.Errorf("unexpected format for active count: %s", formatted2)
	}
}

func TestDrainingDoesNotKillOnConntrackUnknown(t *testing.T) {
	rep := reputation.NewEngine()
	reg := config.RegionConfig{Primary: "JP"}
	sched := NewScheduler(1, 1, rep, reg)

	node := &models.Node{
		ID:     "node-test-unknown",
		IP:     "192.0.2.77",
		Status: models.StatusActive,
	}

	tunnel := &openvpn.Tunnel{
		ID:        "slot-0",
		SlotIndex: 0,
		Interface: "tun0",
		Node:      node,
		State:     "ACTIVE",
	}

	sched.ActiveSlots[0] = tunnel
	sched.TransitionToDraining(0, tunnel)

	// Keep time recent (< 30s timeout)
	tunnel.Mu.Lock()
	tunnel.DrainingStartedAt = time.Now().Add(-5 * time.Second)
	tunnel.Mu.Unlock()

	// Simulate conntrack query failure by pointing to /bin/false
	origCmd := conntrackCmd
	conntrackCmd = "/bin/false"
	defer func() { conntrackCmd = origCmd }()

	// If conntrack returns unknown or query fails, cleanupDrainingSlots MUST NOT kill the tunnel!
	sched.cleanupDrainingSlots()

	// Tunnel MUST still be in DrainingSlots!
	drainingTunnel, exists := sched.DrainingSlots[0]
	if !exists {
		t.Fatalf("Tunnel was prematurely removed from DrainingSlots during conntrack check!")
	}
	if drainingTunnel.State != string(SlotDraining) {
		t.Fatalf("Expected tunnel state to remain DRAINING, got %s", drainingTunnel.State)
	}
}

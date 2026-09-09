package scheduler

import (
	"os/exec"
	"testing"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/openvpn"
	"github.com/NaNA1337/super-proxy/internal/reputation"
)

func TestStandby_WarmPromotionWithoutRestart(t *testing.T) {
	rep := reputation.NewEngine()
	reg := config.RegionConfig{Primary: "JP"}
	sched := NewScheduler(2, 2, rep, reg)

	dummyCmd := exec.Command("true")
	node := &models.Node{
		ID:     "node-warm-standby",
		IP:     "192.0.2.30",
		Status: models.StatusStandby,
	}

	standbyTunnel := &openvpn.Tunnel{
		ID:        "slot-15",
		SlotIndex: 15,
		Interface: "lo",
		Node:      node,
		Cmd:       dummyCmd,
		State:     "ACTIVE", // Tunnel process is running and ready
	}

	sched.StandbyNodes = append(sched.StandbyNodes, standbyTunnel)

	// Trigger reconcile to promote standby into empty slot 0
	sched.reconcileActiveSlots()

	// Verify promoted
	activeTunnel, exists := sched.ActiveSlots[0]
	if !exists {
		t.Fatalf("Expected slot 0 to be filled from standby pool")
	}

	// CRITICAL: Cmd pointer must be identical (no process restart!)
	if activeTunnel.Cmd != dummyCmd {
		t.Fatalf("Warm standby was restarted! activeTunnel.Cmd != original standby Cmd")
	}

	// Slot index updated for routing purposes
	if activeTunnel.SlotIndex != 0 {
		t.Fatalf("Expected SlotIndex to be 0, got %d", activeTunnel.SlotIndex)
	}

	// Standby pool should now be empty
	if len(sched.StandbyNodes) != 0 {
		t.Fatalf("Expected StandbyNodes to be empty, got length %d", len(sched.StandbyNodes))
	}
}

func TestStandby_DeadStandbySkipped(t *testing.T) {
	rep := reputation.NewEngine()
	reg := config.RegionConfig{Primary: "JP"}
	sched := NewScheduler(1, 1, rep, reg)

	deadNode := &models.Node{
		ID:     "node-dead-standby",
		IP:     "192.0.2.31",
		Status: models.StatusStandby,
	}

	deadTunnel := &openvpn.Tunnel{
		ID:        "slot-16",
		SlotIndex: 16,
		Interface: "lo",
		Node:      deadNode,
		State:     "FAILED", // Process crashed while in standby pool
	}

	sched.StandbyNodes = append(sched.StandbyNodes, deadTunnel)

	sched.reconcileActiveSlots()

	// Dead tunnel must NOT be placed in ActiveSlots
	if _, exists := sched.ActiveSlots[0]; exists {
		t.Fatalf("Dead standby tunnel should not be promoted to ActiveSlots")
	}

	// Dead tunnel must be discarded from StandbyNodes
	if len(sched.StandbyNodes) != 0 {
		t.Fatalf("Dead standby tunnel should have been removed from StandbyNodes")
	}
}

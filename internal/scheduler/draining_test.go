package scheduler

import (
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/openvpn"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/NaNA1337/super-proxy/internal/xray"
)

func TestDraining_LifecycleAndState(t *testing.T) {
	rep := reputation.NewEngine()
	reg := config.RegionConfig{Primary: "JP"}
	sched := NewScheduler(3, 2, rep, reg)

	node := &models.Node{
		ID:        "node-drain-1",
		IP:        "192.0.2.1",
		Status:    models.StatusActive,
		FailCount: 0,
	}

	mockTunnel := &openvpn.Tunnel{
		ID:        "slot-0",
		SlotIndex: 0,
		Interface: "tun0",
		Node:      node,
		State:     "ACTIVE",
	}

	sched.ActiveSlots[0] = mockTunnel

	// 1. Move to DRAINING
	sched.TransitionToDraining(0, mockTunnel)

	// Verify ActiveSlots no longer contains slot 0
	if _, exists := sched.ActiveSlots[0]; exists {
		t.Fatalf("Slot 0 should have been removed from ActiveSlots")
	}

	// Verify DrainingSlots contains slot 0
	drainingTunnel, exists := sched.DrainingSlots[0]
	if !exists {
		t.Fatalf("Slot 0 should be in DrainingSlots")
	}
	if drainingTunnel.State != string(SlotDraining) {
		t.Fatalf("Expected tunnel state DRAINING, got %s", drainingTunnel.State)
	}

	// Verify Draining Table ID
	expectedTableID := 200
	if sched.drainingTableIDs[0] != expectedTableID {
		t.Fatalf("Expected draining table ID %d, got %d", expectedTableID, sched.drainingTableIDs[0])
	}

	// 2. Simulate conntrack count > 0 (keep draining)
	// mock cleanup with count > 0 by keeping time recent
	mockTunnel.Mu.Lock()
	mockTunnel.DrainingStartedAt = time.Now()
	mockTunnel.Mu.Unlock()

	// In test environment conntrack returns 0 flows (or command not found)
	// Simulate timeout behavior
	mockTunnel.Mu.Lock()
	mockTunnel.DrainingStartedAt = time.Now().Add(-35 * time.Second) // expired
	mockTunnel.Mu.Unlock()

	sched.cleanupDrainingSlots()

	// After timeout, must be cleaned up from DrainingSlots
	if _, exists := sched.DrainingSlots[0]; exists {
		t.Fatalf("Draining slot should have been removed after timeout")
	}
	if node.Status != models.StatusFailed {
		t.Fatalf("Expected node status FAILED after draining timeout, got %s", node.Status)
	}
}

func TestDraining_StandbyPromotionDoesNotOverwriteDraining(t *testing.T) {
	rep := reputation.NewEngine()
	reg := config.RegionConfig{Primary: "JP"}
	sched := NewScheduler(1, 1, rep, reg)

	oldNode := &models.Node{
		ID:     "node-old",
		IP:     "192.0.2.10",
		Status: models.StatusActive,
	}
	oldTunnel := &openvpn.Tunnel{
		ID:        "slot-0",
		SlotIndex: 0,
		Interface: "tun0",
		Node:      oldNode,
		State:     "ACTIVE",
	}

	sched.ActiveSlots[0] = oldTunnel

	// Drain old tunnel
	sched.TransitionToDraining(0, oldTunnel)

	// Standby tunnel ready to be promoted (use lo interface so kernel accepts route setup in test)
	standbyNode := &models.Node{
		ID:     "node-standby",
		IP:     "192.0.2.20",
		Status: models.StatusStandby,
	}
	standbyTunnel := &openvpn.Tunnel{
		ID:        "slot-15",
		SlotIndex: 15,
		Interface: "lo",
		Node:      standbyNode,
		State:     "ACTIVE",
	}
	sched.StandbyNodes = append(sched.StandbyNodes, standbyTunnel)

	// Promote standby
	sched.reconcileActiveSlots()

	// Verify ActiveSlots now has standby tunnel
	promoted, exists := sched.ActiveSlots[0]
	if !exists || promoted.Node.ID != standbyNode.ID {
		t.Fatalf("Expected standby node to be promoted to slot 0")
	}

	// Verify DrainingSlots STILL has the old tunnel!
	draining, exists := sched.DrainingSlots[0]
	if !exists || draining.Node.ID != oldNode.ID {
		t.Fatalf("Draining tunnel must remain intact in DrainingSlots after standby promotion")
	}

	// Verify distinct table IDs:
	// Slot 0 active table is 100, draining table is 200
	if sched.drainingTableIDs[0] != 200 {
		t.Fatalf("Expected draining table 200, got %d", sched.drainingTableIDs[0])
	}
}

func TestDraining_XrayActiveSetCoordination(t *testing.T) {
	tempDir := t.TempDir()
	configPath := tempDir + "/xray_drain_test.json"
	apiPort := 10095
	socksPort := 10895

	if err := xray.GenerateConfigWithOptions(xray.ConfigOptions{
		SlotCount:   2,
		ConfigPath:  configPath,
		ApiPort:     apiPort,
		SocksListen: "127.0.0.1",
		SocksPort:   socksPort,
	}); err != nil {
		t.Fatalf("failed to generate test config: %v", err)
	}

	xsup := xray.NewSupervisor(configPath, apiPort, "127.0.0.1", socksPort, 2)
	if err := xsup.Start(); err != nil {
		t.Fatalf("failed to start xray: %v", err)
	}
	defer xsup.Stop()

	rep := reputation.NewEngine()
	reg := config.RegionConfig{Primary: "JP"}
	sched := NewScheduler(2, 2, rep, reg)
	sched.SetXraySupervisor(xsup)

	mockTunnel := &openvpn.Tunnel{
		ID:        "slot-0",
		SlotIndex: 0,
		Interface: "tun0",
		Node: &models.Node{
			ID:     "node-xray-1",
			IP:     "192.0.2.1",
			Status: models.StatusActive,
		},
		State: "ACTIVE",
	}
	sched.ActiveSlots[0] = mockTunnel
	if err := xsup.ActivateSlot(0); err != nil {
		t.Fatalf("failed to activate slot 0 in xray: %v", err)
	}

	// Initially exit-0 is active in Xray
	if !xsup.IsOutboundActive("exit-0") {
		t.Fatalf("expected exit-0 to be active initially")
	}

	// Move slot 0 to DRAINING
	sched.TransitionToDraining(0, mockTunnel)

	// In Xray, exit-0 MUST be immediately disabled so new connections do not enter draining tunnel
	if xsup.IsOutboundActive("exit-0") {
		t.Fatalf("expected exit-0 to be disabled in Xray active set after TransitionToDraining")
	}

	// Slot controller must also reflect OutboundActive == false
	sc, err := sched.Slots.GetSlot(0)
	if err != nil {
		t.Fatalf("failed to get slot 0: %v", err)
	}
	sc.Mu.RLock()
	outboundActive := sc.OutboundActive
	sc.Mu.RUnlock()
	if outboundActive {
		t.Fatalf("expected SlotController.OutboundActive to be false")
	}

	// Simulate standby promotion to slot 0
	standbyTunnel := &openvpn.Tunnel{
		ID:        "slot-16",
		SlotIndex: 16,
		Interface: "lo",
		Node: &models.Node{
			ID:     "node-xray-2",
			IP:     "192.0.2.2",
			Status: models.StatusStandby,
		},
		State: "ACTIVE",
	}
	sched.StandbyNodes = append(sched.StandbyNodes, standbyTunnel)

	sched.reconcileActiveSlots()

	// After promotion, exit-0 MUST be restored to active set in Xray
	if !xsup.IsOutboundActive("exit-0") {
		t.Fatalf("expected exit-0 to be re-enabled in Xray active set after standby promotion")
	}

	sc.Mu.RLock()
	outboundActiveAfter := sc.OutboundActive
	sc.Mu.RUnlock()
	if !outboundActiveAfter {
		t.Fatalf("expected SlotController.OutboundActive to be true after standby promotion")
	}
}

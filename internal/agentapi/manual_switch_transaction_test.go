package agentapi

import (
	"testing"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/openvpn"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/NaNA1337/super-proxy/internal/scheduler"
	"github.com/stretchr/testify/require"
)

// TestManualSwitch_TargetNotFound_PreservesActiveTunnel verifies that if the target
// node does not exist in the database, the old ACTIVE tunnel is never disturbed or moved to DRAINING.
func TestManualSwitch_TargetNotFound_PreservesActiveTunnel(t *testing.T) {
	require.NoError(t, database.InitDatabase(":memory:"))

	s := scheduler.NewScheduler(3, 2, reputation.NewEngine(), config.RegionConfig{Primary: "JP"})
	SetScheduler(s)
	defer SetScheduler(nil)

	oldNode := &models.Node{ID: "healthy-active-node", IP: "198.51.100.10", Status: models.StatusActive}
	require.NoError(t, database.DB.Create(oldNode).Error)

	oldTunnel := &openvpn.Tunnel{Node: oldNode, Interface: "tun0", State: "ACTIVE", SlotIndex: 0}
	s.ActiveSlots[0] = oldTunnel

	sc, err := s.Slots.GetSlot(0)
	require.NoError(t, err)
	sc.ActiveTunnel = oldTunnel
	sc.State = scheduler.SlotActive

	op := createSwitchOperation("test-not-found", 0, "non-existent-target")
	lease, err := s.Slots.TryAcquireSlot(0, "manual-switch", op.ID)
	require.NoError(t, err)

	executeManualSwitch(op, lease)

	result, ok := getOperation(op.ID)
	require.True(t, ok)
	require.Equal(t, OpFailed, result.Status)
	require.Contains(t, result.Error, "not found")

	// Verify old ACTIVE tunnel was NEVER drained or removed
	s.Mu.Lock()
	defer s.Mu.Unlock()
	require.Contains(t, s.ActiveSlots, 0)
	require.Equal(t, "healthy-active-node", s.ActiveSlots[0].Node.ID)
	require.NotContains(t, s.DrainingSlots, 0)
}

// TestManualSwitch_CandidateFailure_PreservesActiveTunnel verifies that if candidate
// connection fails (e.g. bad credentials), the old ACTIVE tunnel remains completely healthy.
func TestManualSwitch_CandidateFailure_PreservesActiveTunnel(t *testing.T) {
	require.NoError(t, database.InitDatabase(":memory:"))

	s := scheduler.NewScheduler(3, 2, reputation.NewEngine(), config.RegionConfig{Primary: "JP"})
	SetScheduler(s)
	defer SetScheduler(nil)

	oldNode := &models.Node{ID: "active-node-1", IP: "198.51.100.20", Status: models.StatusActive}
	require.NoError(t, database.DB.Create(oldNode).Error)

	oldTunnel := &openvpn.Tunnel{Node: oldNode, Interface: "tun0", State: "ACTIVE", SlotIndex: 0}
	s.ActiveSlots[0] = oldTunnel

	// Create candidate node with broken config that will fail to start
	candidateNode := &models.Node{
		ID:      "broken-candidate",
		IP:      "203.0.113.99",
		Status:  models.StatusDiscovered,
		OpenVPN: "invalid base64 content",
	}
	require.NoError(t, database.DB.Create(candidateNode).Error)

	op := createSwitchOperation("test-candidate-fail", 0, candidateNode.ID)
	lease, err := s.Slots.TryAcquireSlot(0, "manual-switch", op.ID)
	require.NoError(t, err)

	executeManualSwitch(op, lease)

	result, ok := getOperation(op.ID)
	require.True(t, ok)
	require.Equal(t, OpFailed, result.Status)

	// Old ACTIVE tunnel must still be active!
	s.Mu.Lock()
	defer s.Mu.Unlock()
	require.Contains(t, s.ActiveSlots, 0)
	require.Equal(t, "active-node-1", s.ActiveSlots[0].Node.ID)
	require.NotContains(t, s.DrainingSlots, 0)
}

// TestManualSwitch_SelfSwitch_Rejected verifies that switching to the same node that
// is already active on the slot is rejected in pre-flight without touching the slot.
func TestManualSwitch_SelfSwitch_Rejected(t *testing.T) {
	require.NoError(t, database.InitDatabase(":memory:"))

	s := scheduler.NewScheduler(3, 2, reputation.NewEngine(), config.RegionConfig{Primary: "JP"})
	SetScheduler(s)
	defer SetScheduler(nil)

	activeNode := &models.Node{ID: "self-node", IP: "198.51.100.30", Status: models.StatusActive}
	require.NoError(t, database.DB.Create(activeNode).Error)

	activeTunnel := &openvpn.Tunnel{Node: activeNode, Interface: "tun0", State: "ACTIVE", SlotIndex: 0}
	s.ActiveSlots[0] = activeTunnel

	op := createSwitchOperation("test-self-switch", 0, activeNode.ID)
	lease, err := s.Slots.TryAcquireSlot(0, "manual-switch", op.ID)
	require.NoError(t, err)

	executeManualSwitch(op, lease)

	result, ok := getOperation(op.ID)
	require.True(t, ok)
	require.Equal(t, OpFailed, result.Status)
	require.Contains(t, result.Error, "already active")

	s.Mu.Lock()
	defer s.Mu.Unlock()
	require.Equal(t, "self-node", s.ActiveSlots[0].Node.ID)
	require.NotContains(t, s.DrainingSlots, 0)
}

// TestManualSwitch_ConcurrentAcquireRejection verifies that two concurrent switch requests
// on the same slot result in exactly one acquisition, preventing split-brain operations.
func TestManualSwitch_ConcurrentAcquireRejection(t *testing.T) {
	s := scheduler.NewScheduler(3, 2, reputation.NewEngine(), config.RegionConfig{Primary: "JP"})

	lease1, err1 := s.Slots.TryAcquireSlot(0, "manual-switch", "op-1")
	require.NoError(t, err1)
	require.NotNil(t, lease1)

	// Second acquisition while lease1 is active must fail
	lease2, err2 := s.Slots.TryAcquireSlot(0, "manual-switch", "op-2")
	require.Error(t, err2)
	require.Nil(t, lease2)
	require.Contains(t, err2.Error(), "SLOT_BUSY")

	// After lease1 is released, new acquisition succeeds
	lease1.Release()

	lease3, err3 := s.Slots.TryAcquireSlot(0, "manual-switch", "op-3")
	require.NoError(t, err3)
	require.NotNil(t, lease3)
	lease3.Release()
}

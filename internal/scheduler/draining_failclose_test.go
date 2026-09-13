package scheduler

import (
	"errors"
	"testing"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/openvpn"
	"github.com/NaNA1337/super-proxy/internal/reputation"
)

func TestScheduler_DrainingRoutingFailClosed(t *testing.T) {
	sched := NewScheduler(3, 2, reputation.NewEngine(), config.RegionConfig{Primary: "JP"})

	node := &models.Node{
		ID:     "198.51.100.99",
		IP:     "198.51.100.99",
		Status: models.StatusActive,
	}

	tunnel := &openvpn.Tunnel{
		ID:        "slot-0",
		SlotIndex: 0,
		Interface: "tun0",
		Node:      node,
		State:     string(SlotActive),
	}

	sched.Mu.Lock()
	sched.ActiveSlots[0] = tunnel
	// Inject failing routing setup
	sched.SetupDrainingRoutingFn = func(drainingTableID int, interfaceName string, tunIP string) error {
		return errors.New("simulated routing failure (ip rule/route error)")
	}

	// Trigger draining transition
	sched.transitionToDrainingLocked(0, tunnel)
	sched.Mu.Unlock()

	// INVARIANT 1: Slot MUST NOT be in DrainingSlots
	sched.Mu.Lock()
	defer sched.Mu.Unlock()

	if _, inDraining := sched.DrainingSlots[0]; inDraining {
		t.Fatalf("FAIL-CLOSED VIOLATION: Slot 0 was placed in DrainingSlots despite routing setup failure")
	}

	// INVARIANT 2: Slot MUST remain in ActiveSlots
	activeTun, inActive := sched.ActiveSlots[0]
	if !inActive || activeTun == nil {
		t.Fatalf("FAIL-CLOSED VIOLATION: Slot 0 was removed from ActiveSlots after routing setup failure")
	}

	// INVARIANT 3: Tunnel state MUST be reverted to SlotActive
	tunnel.Mu.Lock()
	st := tunnel.State
	tunnel.Mu.Unlock()
	if st != string(SlotActive) {
		t.Fatalf("FAIL-CLOSED VIOLATION: Tunnel state is %s, expected reverted state %s", st, SlotActive)
	}

	// INVARIANT 4: Node status MUST NOT be StatusDraining
	if node.Status == models.StatusDraining {
		t.Fatalf("FAIL-CLOSED VIOLATION: Node status was set to DRAINING despite routing failure")
	}
}

func TestScheduler_ExitedTunnelIsRetiredWithoutDrainingRoute(t *testing.T) {
	sched := NewScheduler(1, 0, reputation.NewEngine(), config.RegionConfig{Primary: "JP"})
	node := &models.Node{ID: "dead-node", IP: "192.0.2.55", Status: models.StatusActive}
	tunnel := &openvpn.Tunnel{
		ID:        "slot-0",
		SlotIndex: 0,
		Interface: "tun-missing",
		Node:      node,
		State:     string(SlotFailed),
	}
	sched.ActiveSlots[0] = tunnel
	routingCalled := false
	sched.SetupDrainingRoutingFn = func(int, string, string) error {
		routingCalled = true
		return nil
	}

	sched.Mu.Lock()
	sched.transitionToDrainingLocked(0, tunnel)
	sched.Mu.Unlock()

	if routingCalled {
		t.Fatal("an exited tunnel must not enter draining routing")
	}
	if _, exists := sched.ActiveSlots[0]; exists {
		t.Fatal("exited tunnel remained in active slots")
	}
	if _, exists := sched.DrainingSlots[0]; exists {
		t.Fatal("exited tunnel was incorrectly moved to draining slots")
	}
	sc, _ := sched.Slots.GetSlot(0)
	if sc.State != SlotFailed || sc.ActiveTunnel != nil || sc.OutboundActive {
		t.Fatalf("slot was not reset after tunnel exit: state=%s active=%v outbound=%v", sc.State, sc.ActiveTunnel != nil, sc.OutboundActive)
	}
}

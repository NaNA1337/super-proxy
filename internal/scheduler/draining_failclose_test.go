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

package scheduler

import (
	"sync"
	"testing"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/openvpn"
	"github.com/NaNA1337/super-proxy/internal/reputation"
)

func TestManualSwitch_TwoSimultaneousRequests(t *testing.T) {
	sm := NewSlotManager(3)

	// Simulate request 1 acquiring slot 0
	lease1, err := sm.TryAcquireSlot(0, "manual-user-1", "op-req-1")
	if err != nil {
		t.Fatalf("Expected request 1 to succeed, got %v", err)
	}

	// Simultaneous request 2 to slot 0 MUST fail with conflict
	lease2, err := sm.TryAcquireSlot(0, "manual-user-2", "op-req-2")
	if err == nil {
		t.Fatalf("Expected request 2 to be rejected due to busy slot, but it succeeded")
	}
	if lease2 != nil {
		t.Fatalf("Lease 2 should be nil on conflict")
	}

	// Release request 1
	lease1.Release()

	// Subsequent request 3 can now succeed
	lease3, err := sm.TryAcquireSlot(0, "manual-user-3", "op-req-3")
	if err != nil {
		t.Fatalf("Expected request 3 to succeed after release, got %v", err)
	}
	lease3.Release()
}

func TestManualSwitch_FailoverDoesNotPreemptManualLock(t *testing.T) {
	rep := reputation.NewEngine()
	reg := config.RegionConfig{Primary: "JP"}
	sched := NewScheduler(1, 1, rep, reg)

	node := &models.Node{
		ID:     "node-slot-0",
		IP:     "192.0.2.50",
		Status: models.StatusActive,
	}
	tunnel := &openvpn.Tunnel{
		ID:        "slot-0",
		SlotIndex: 0,
		Interface: "lo",
		Node:      node,
		State:     "FAILED", // Tunnel is dead, health check will fail
	}
	sched.ActiveSlots[0] = tunnel

	// Manually lock slot 0 for manual switch operation
	sched.Mu.Lock()
	sched.ManualOverride[0] = true
	sched.Mu.Unlock()

	// Run reconcileActiveSlots (auto failover loop)
	sched.reconcileActiveSlots()

	// Because ManualOverride[0] is true, auto failover must SKIP this slot!
	sched.Mu.Lock()
	activeTunnel := sched.ActiveSlots[0]
	drainingCount := len(sched.DrainingSlots)
	sched.Mu.Unlock()

	if drainingCount != 0 {
		t.Fatalf("Auto-failover should not have transitioned slot 0 to DRAINING while ManualOverride is active")
	}
	if activeTunnel != tunnel {
		t.Fatalf("ActiveSlots[0] should not have been altered while under ManualOverride")
	}
}

func TestManualSwitch_StaleGenerationRejected(t *testing.T) {
	sm := NewSlotManager(1)

	sc, _ := sm.GetSlot(0)

	// Op 1 acquires generation 1
	lease1, _ := sm.TryAcquireSlot(0, "manual-op-1", "op-1")
	lease1.Release()

	// Op 2 acquires generation 2
	lease2, _ := sm.TryAcquireSlot(0, "manual-op-2", "op-2")

	// If Op 1's delayed background goroutine attempts to validate lease1:
	if sc.ValidateLease(lease1) {
		t.Fatalf("Stale lease1 (gen 1) must be rejected against current gen %d", lease2.Generation)
	}

	// Lease 2 is current and valid
	if !sc.ValidateLease(lease2) {
		t.Fatalf("Current lease2 (gen 2) must be validated successfully")
	}

	lease2.Release()
}

func TestManualSwitch_HighConcurrencyRace(t *testing.T) {
	sm := NewSlotManager(3)
	workers := 100
	var wg sync.WaitGroup

	acquiredPerSlot := make(map[int]int)
	var mu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			slot := id % 3
			lease, err := sm.TryAcquireSlot(slot, "concurrent-worker", "op")
			if err == nil {
				mu.Lock()
				acquiredPerSlot[slot]++
				mu.Unlock()
				lease.Release()
			}
		}(i)
	}

	wg.Wait()

	for slot := 0; slot < 3; slot++ {
		sc, _ := sm.GetSlot(slot)
		sc.Mu.RLock()
		owner := sc.Owner
		sc.Mu.RUnlock()
		if owner != "" {
			t.Errorf("Slot %d owner not released after concurrent test: %s", slot, owner)
		}
	}
}

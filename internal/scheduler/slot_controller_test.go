package scheduler

import (
	"sync"
	"testing"
)

func TestSlotController_LeaseAndGeneration(t *testing.T) {
	sm := NewSlotManager(3)

	// Acquire slot 0
	lease1, err := sm.TryAcquireSlot(0, "manual-1", "op-1")
	if err != nil {
		t.Fatalf("Expected successful acquire, got %v", err)
	}
	if lease1.Generation != 1 {
		t.Fatalf("Expected generation 1, got %d", lease1.Generation)
	}

	// Simultaneous request to slot 0 must be rejected (409 SLOT_BUSY)
	_, err = sm.TryAcquireSlot(0, "manual-2", "op-2")
	if err == nil {
		t.Fatalf("Expected conflict error on busy slot, got nil")
	}

	// Slot 1 can still be acquired independently
	lease2, err := sm.TryAcquireSlot(1, "manual-2", "op-2")
	if err != nil {
		t.Fatalf("Expected successful acquire on slot 1, got %v", err)
	}
	if lease2.SlotID != 1 {
		t.Fatalf("Expected slot 1, got %d", lease2.SlotID)
	}

	// Release slot 0
	lease1.Release()

	// Re-acquire slot 0 -> generation must increment to 2
	lease3, err := sm.TryAcquireSlot(0, "failover-1", "op-3")
	if err != nil {
		t.Fatalf("Expected successful re-acquire of slot 0, got %v", err)
	}
	if lease3.Generation != 2 {
		t.Fatalf("Expected generation 2, got %d", lease3.Generation)
	}

	// Old lease1 must now be invalid
	sc, _ := sm.GetSlot(0)
	if sc.ValidateLease(lease1) {
		t.Fatalf("Old lease with generation 1 should be invalid, but validated successfully")
	}
	if !sc.ValidateLease(lease3) {
		t.Fatalf("Current lease with generation 2 should be valid")
	}

	lease3.Release()
	lease2.Release()
}

func TestSlotController_ConcurrentAcquireContention(t *testing.T) {
	sm := NewSlotManager(1)
	workers := 50
	var wg sync.WaitGroup

	successCount := 0
	var countMu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			lease, err := sm.TryAcquireSlot(0, "worker", "op")
			if err == nil {
				countMu.Lock()
				successCount++
				countMu.Unlock()
				// Immediately release to allow another
				lease.Release()
			}
		}(i)
	}

	wg.Wait()

	// At least one won, and all releases were clean
	sc, _ := sm.GetSlot(0)
	sc.Mu.RLock()
	owner := sc.Owner
	sc.Mu.RUnlock()

	if owner != "" {
		t.Errorf("Expected owner to be empty after all releases, got %s", owner)
	}
	if successCount == 0 {
		t.Errorf("Expected at least 1 successful lease acquisition, got 0")
	}
}

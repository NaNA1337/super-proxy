package scheduler

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/NaNA1337/super-proxy/internal/openvpn"
)

// SlotLease represents an exclusive ownership lease for modifying a slot.
// Any stale operations with an older generation are automatically rejected.
type SlotLease struct {
	SlotID      int
	Generation  uint64
	Owner       string
	OperationID string
	AcquiredAt  time.Time
	controller  *SlotController
}

// Release yields the slot lease if generation matches
func (l *SlotLease) Release() {
	if l == nil || l.controller == nil {
		return
	}
	l.controller.ReleaseLease(l)
}

// SlotController manages the state, generation, and ownership of a single egress slot.
type SlotController struct {
	SlotID          int
	Mu              sync.RWMutex
	Generation      uint64
	Owner           string
	OperationID     string
	State           SlotState
	ActiveTunnel    *openvpn.Tunnel
	DrainingTunnel  *openvpn.Tunnel
	DrainingTableID int
	OutboundActive  bool
	UpdatedAt       time.Time
}

// NewSlotController creates a controller for a slot
func NewSlotController(slotID int) *SlotController {
	return &SlotController{
		SlotID:    slotID,
		State:     SlotOffline,
		UpdatedAt: time.Now(),
	}
}

// TryAcquire atomically checks and reserves slot ownership in a single synchronization boundary.
func (sc *SlotController) TryAcquire(owner, opID string) (*SlotLease, error) {
	sc.Mu.Lock()
	defer sc.Mu.Unlock()

	if sc.Owner != "" {
		return nil, fmt.Errorf("SLOT_BUSY: slot %d currently locked by owner '%s' (op: %s, generation: %d)",
			sc.SlotID, sc.Owner, sc.OperationID, sc.Generation)
	}

	sc.Generation++
	sc.Owner = owner
	sc.OperationID = opID
	sc.UpdatedAt = time.Now()

	log.Printf("[SlotController-%d] Acquired by %s (op: %s, generation: %d)",
		sc.SlotID, owner, opID, sc.Generation)

	return &SlotLease{
		SlotID:      sc.SlotID,
		Generation:  sc.Generation,
		Owner:       owner,
		OperationID: opID,
		AcquiredAt:  time.Now(),
		controller:  sc,
	}, nil
}

// ReleaseLease releases the lock if the lease matches current generation
func (sc *SlotController) ReleaseLease(lease *SlotLease) {
	sc.Mu.Lock()
	defer sc.Mu.Unlock()

	if sc.Generation != lease.Generation || sc.OperationID != lease.OperationID {
		log.Printf("[SlotController-%d] Ignoring stale lease release (current gen %d != lease gen %d)",
			sc.SlotID, sc.Generation, lease.Generation)
		return
	}

	log.Printf("[SlotController-%d] Released by %s (generation %d)",
		sc.SlotID, sc.Owner, sc.Generation)
	sc.Owner = ""
	sc.OperationID = ""
	sc.UpdatedAt = time.Now()
}

// ValidateLease verifies if the lease is still valid and not preempted
func (sc *SlotController) ValidateLease(lease *SlotLease) bool {
	sc.Mu.RLock()
	defer sc.Mu.RUnlock()
	return sc.Generation == lease.Generation && sc.OperationID == lease.OperationID && sc.Owner == lease.Owner
}

// SlotManager manages all slot controllers across the scheduler
type SlotManager struct {
	mu    sync.RWMutex
	slots map[int]*SlotController
}

func NewSlotManager(maxActive int) *SlotManager {
	sm := &SlotManager{
		slots: make(map[int]*SlotController, maxActive),
	}
	for i := 0; i < maxActive; i++ {
		sm.slots[i] = NewSlotController(i)
	}
	return sm
}

func (sm *SlotManager) GetSlot(slotID int) (*SlotController, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sc, exists := sm.slots[slotID]
	if !exists {
		return nil, fmt.Errorf("slot %d does not exist", slotID)
	}
	return sc, nil
}

func (sm *SlotManager) TryAcquireSlot(slotID int, owner, opID string) (*SlotLease, error) {
	sc, err := sm.GetSlot(slotID)
	if err != nil {
		return nil, err
	}
	return sc.TryAcquire(owner, opID)
}

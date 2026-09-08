package agentapi

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/health"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/openvpn"
	"github.com/NaNA1337/super-proxy/internal/routing"
	"github.com/google/uuid"
)

type OperationStatus string

const (
	OpRequested  OperationStatus = "REQUESTED"
	OpPreparing  OperationStatus = "PREPARING"
	OpConnecting OperationStatus = "CONNECTING"
	OpVerifying  OperationStatus = "VERIFYING"
	OpActive     OperationStatus = "ACTIVE"
	OpFailed     OperationStatus = "FAILED"
)

type SwitchOperation struct {
	ID        string          `json:"operation_id"`
	Slot      int             `json:"slot"`
	TargetID  string          `json:"target_node_id"`
	Status    OperationStatus `json:"status"`
	Error     string          `json:"error,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

var (
	opsMu sync.RWMutex
	ops   = make(map[string]*SwitchOperation)
)

func createSwitchOperation(slot int, targetNodeID string) *SwitchOperation {
	op := &SwitchOperation{
		ID:        uuid.New().String(),
		Slot:      slot,
		TargetID:  targetNodeID,
		Status:    OpRequested,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	opsMu.Lock()
	ops[op.ID] = op
	opsMu.Unlock()
	return op
}

func getOperation(id string) (*SwitchOperation, bool) {
	opsMu.RLock()
	defer opsMu.RUnlock()
	op, exists := ops[id]
	return op, exists
}

func updateOpStatus(op *SwitchOperation, status OperationStatus, errStr string) {
	opsMu.Lock()
	defer opsMu.Unlock()
	op.Status = status
	if errStr != "" {
		op.Error = errStr
	}
	op.UpdatedAt = time.Now()
}

// executeManualSwitch executes the state machine for manual slot switching
func executeManualSwitch(op *SwitchOperation) {
	log.Printf("[Operation-%s] Starting manual switch for slot %d -> node %s", op.ID, op.Slot, op.TargetID)
	
	// 1. PREPARING
	updateOpStatus(op, OpPreparing, "")
	
	// Lock the scheduler for this slot
	sched.Mu.Lock()
	sched.ManualOverride[op.Slot] = true
	
	// Clean up old tunnel if it exists
	if oldTunnel, exists := sched.ActiveSlots[op.Slot]; exists {
		routing.ClearSlotRouting(op.Slot)
		oldTunnel.Stop()
		delete(sched.ActiveSlots, op.Slot)
	}
	sched.Mu.Unlock()
	
	// Fetch node from DB
	var node models.Node
	if result := database.DB.Where("id = ?", op.TargetID).First(&node); result.Error != nil {
		updateOpStatus(op, OpFailed, "Node not found in DB")
		releaseSlot(op.Slot)
		return
	}

	// 2. CONNECTING
	updateOpStatus(op, OpConnecting, "")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Fix gosec context cancellation warning

	tunnel, err := openvpn.StartTunnel(ctx, op.Slot, &node)
	if err != nil {
		updateOpStatus(op, OpFailed, fmt.Sprintf("Failed to start tunnel: %v", err))
		releaseSlot(op.Slot)
		return
	}

	// Give it time to establish tun device
	time.Sleep(5 * time.Second)

	// 3. VERIFYING
	updateOpStatus(op, OpVerifying, "")
	// Setup routing first so we can verify
	if err := routing.SetupSlotRouting(op.Slot, tunnel.Interface); err != nil {
		updateOpStatus(op, OpFailed, fmt.Sprintf("Failed to setup routing: %v", err))
		tunnel.Stop()
		releaseSlot(op.Slot)
		return
	}

	// Perform health check
	checkCtx, checkCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer checkCancel()
	ok, _, err := health.CheckTunnelConnectivity(checkCtx, tunnel.Interface, "http://1.1.1.1")
	if !ok || err != nil {
		updateOpStatus(op, OpFailed, fmt.Sprintf("Health check failed on tun dev %s", tunnel.Interface))
		routing.ClearSlotRouting(op.Slot)
		tunnel.Stop()
		releaseSlot(op.Slot)
		return
	}

	// 4. ACTIVE
	sched.Mu.Lock()
	sched.ActiveSlots[op.Slot] = tunnel
	// Release the manual override so Scheduler can monitor it again
	sched.ManualOverride[op.Slot] = false
	sched.Mu.Unlock()
	
	updateOpStatus(op, OpActive, "")
	log.Printf("[Operation-%s] Manual switch complete.", op.ID)
}

func releaseSlot(slot int) {
	sched.Mu.Lock()
	sched.ManualOverride[slot] = false
	sched.Mu.Unlock()
}

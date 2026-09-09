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

func init() {
	// Start operation cleanup goroutine to prevent memory leak
	go cleanupOldOperations()
}

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

// cleanupOldOperations removes completed operations older than 1 hour to prevent memory leak
func cleanupOldOperations() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		opsMu.Lock()
		cutoff := time.Now().Add(-1 * time.Hour)
		for id, op := range ops {
			if (op.Status == OpActive || op.Status == OpFailed) && op.UpdatedAt.Before(cutoff) {
				delete(ops, id)
			}
		}
		opsMu.Unlock()
	}
}

// executeManualSwitch executes the state machine for manual slot switching
func executeManualSwitch(op *SwitchOperation) {
	log.Printf("[Operation-%s] Starting manual switch for slot %d -> node %s", op.ID, op.Slot, op.TargetID)

	// 1. PREPARING — Clean up old tunnel under lock
	updateOpStatus(op, OpPreparing, "")

	sched.Mu.Lock()
	if oldTunnel, exists := sched.ActiveSlots[op.Slot]; exists {
		routing.ClearSlotRouting(op.Slot)
		oldTunnel.Stop()
		delete(sched.ActiveSlots, op.Slot)
		// Update old node status in DB
		database.DB.Model(oldTunnel.Node).Update("status", models.StatusFailed)
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
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

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
	res := health.VerifyTunnel(ctx, op.Slot, tunnel.Interface, routing.BaseTableID+op.Slot, &node)

	if !res.TunnelHealthy || res.Error != nil {
		updateOpStatus(op, OpFailed, fmt.Sprintf("Health check failed on tun dev %s: %v", tunnel.Interface, res.Error))
		routing.ClearSlotRouting(op.Slot)
		tunnel.Stop()
		releaseSlot(op.Slot)
		return
	}

	// 4. ACTIVE — Re-acquire lock and check for conflicts before committing
	sched.Mu.Lock()

	// Check if auto-scheduler filled this slot while we were connecting
	if conflictTunnel, exists := sched.ActiveSlots[op.Slot]; exists {
		// Auto-scheduler promoted a standby. Our manually connected tunnel wins,
		// but we must clean up the conflict.
		log.Printf("[Operation-%s] Conflict: auto-scheduler filled slot %d during manual switch. Replacing.", op.ID, op.Slot)
		routing.ClearSlotRouting(op.Slot)
		conflictTunnel.Stop()
	}

	sched.ActiveSlots[op.Slot] = tunnel
	database.DB.Model(&node).Update("status", models.StatusActive)

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

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
	"github.com/NaNA1337/super-proxy/internal/scheduler"
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

// executeManualSwitch executes the state machine for manual slot switching.
// GUARANTEE: Never bypasses DRAINING. Old tunnels always enter DRAINING first.
func executeManualSwitch(op *SwitchOperation, lease *scheduler.SlotLease) {
	log.Printf("[Operation-%s] Starting manual switch for slot %d -> node %s (generation: %d)",
		op.ID, op.Slot, op.TargetID, lease.Generation)

	// 1. PREPARING — Move old tunnel to DRAINING without killing existing connections
	updateOpStatus(op, OpPreparing, "")

	sched.Mu.Lock()
	if oldTunnel, exists := sched.ActiveSlots[op.Slot]; exists {
		log.Printf("[Operation-%s] Moving old tunnel %s to DRAINING (preserving connections)", op.ID, oldTunnel.Node.IP)
		sched.TransitionToDraining(op.Slot, oldTunnel)
	}
	sched.Mu.Unlock()

	// Fetch target node from DB
	var node models.Node
	if result := database.DB.Where("id = ?", op.TargetID).First(&node); result.Error != nil {
		updateOpStatus(op, OpFailed, "Node not found in DB")
		lease.Release()
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
		_ = scheduler.TransitionNode(database.DB, &node, models.StatusFailed)
		lease.Release()
		releaseSlot(op.Slot)
		return
	}

	// Give it time to establish tun device
	time.Sleep(5 * time.Second)

	// 3. VERIFYING
	updateOpStatus(op, OpVerifying, "")
	if err := routing.SetupSlotRouting(op.Slot, tunnel.Interface); err != nil {
		updateOpStatus(op, OpFailed, fmt.Sprintf("Failed to setup routing: %v", err))
		tunnel.Stop()
		_ = scheduler.TransitionNode(database.DB, &node, models.StatusFailed)
		lease.Release()
		releaseSlot(op.Slot)
		return
	}

	// Perform end-to-end health check
	res := health.VerifyTunnel(ctx, op.Slot, tunnel.Interface, routing.BaseTableID+op.Slot, &node)
	if !res.TunnelHealthy || res.Error != nil {
		updateOpStatus(op, OpFailed, fmt.Sprintf("Health check failed on tun dev %s: %v", tunnel.Interface, res.Error))
		routing.ClearSlotRouting(op.Slot)
		tunnel.Stop()
		_ = scheduler.TransitionNode(database.DB, &node, models.StatusFailed)
		lease.Release()
		releaseSlot(op.Slot)
		return
	}

	// Transition node to QUALIFIED
	_ = scheduler.TransitionNode(database.DB, &node, models.StatusQualified)

	// 4. ACTIVE — Re-acquire lock and validate lease generation
	sched.Mu.Lock()
	defer sched.Mu.Unlock()

	sc, _ := sched.Slots.GetSlot(op.Slot)
	if sc != nil && !sc.ValidateLease(lease) {
		log.Printf("[Operation-%s] Stale lease detected! Preempted by newer operation. Aborting.", op.ID)
		routing.ClearSlotRouting(op.Slot)
		tunnel.Stop()
		lease.Release()
		releaseSlot(op.Slot)
		updateOpStatus(op, OpFailed, "Operation preempted by newer request")
		return
	}

	// If conflict tunnel exists, drain it safely
	if conflictTunnel, exists := sched.ActiveSlots[op.Slot]; exists && conflictTunnel != tunnel {
		log.Printf("[Operation-%s] Conflict tunnel on slot %d safely transitioned to DRAINING", op.ID, op.Slot)
		sched.TransitionToDraining(op.Slot, conflictTunnel)
	}

	sched.ActiveSlots[op.Slot] = tunnel
	_ = scheduler.TransitionNode(database.DB, &node, models.StatusActive)

	if sc != nil {
		sc.Mu.Lock()
		sc.ActiveTunnel = tunnel
		sc.State = scheduler.SlotActive
		sc.OutboundActive = true
		sc.Mu.Unlock()
	}

	if sched.XraySupervisor != nil {
		tag := fmt.Sprintf("exit-%d", op.Slot)
		if err := sched.XraySupervisor.EnableOutbound(tag, routing.BaseTableID+op.Slot); err != nil {
			log.Printf("[Operation-%s] Warning: failed to enable Xray outbound %s: %v", op.ID, tag, err)
		}
	}

	lease.Release()
	sched.ManualOverride[op.Slot] = false

	updateOpStatus(op, OpActive, "")
	log.Printf("[Operation-%s] Manual switch complete successfully (Node %s ACTIVE on Slot %d).",
		op.ID, node.IP, op.Slot)
}

func releaseSlot(slot int) {
	sched.Mu.Lock()
	sched.ManualOverride[slot] = false
	sched.Mu.Unlock()
}

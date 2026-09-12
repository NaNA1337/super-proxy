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

func createSwitchOperation(id string, slot int, targetNodeID string) *SwitchOperation {
	op := &SwitchOperation{
		ID:        id,
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
	if !exists {
		return nil, false
	}
	snapshot := *op
	return &snapshot, true
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
// GUARANTEE: Non-destructive candidate preparation.
// The old ACTIVE tunnel is NEVER disturbed or drained until the candidate tunnel has
// successfully connected, established its tun interface, passed isolated policy routing
// health checks, and passed atomic cutover.
func executeManualSwitch(op *SwitchOperation, lease *scheduler.SlotLease) {
	log.Printf("[Operation-%s] Starting transactional manual switch for slot %d -> node %s (generation: %d)",
		op.ID, op.Slot, op.TargetID, lease.Generation)

	// 1. PRE-FLIGHT VALIDATION — Validate target node BEFORE touching anything
	updateOpStatus(op, OpPreparing, "")

	var node models.Node
	if result := database.DB.Where("id = ?", op.TargetID).First(&node); result.Error != nil {
		log.Printf("[Operation-%s] Pre-flight rejected: target node %s not found in DB", op.ID, op.TargetID)
		updateOpStatus(op, OpFailed, "Target node not found in DB")
		lease.Release()
		releaseSlot(op.Slot)
		return
	}

	sched.Mu.Lock()
	currentActive, hasCurrent := sched.ActiveSlots[op.Slot]
	sched.Mu.Unlock()

	if hasCurrent && currentActive != nil && currentActive.Node != nil && currentActive.Node.ID == op.TargetID {
		log.Printf("[Operation-%s] Pre-flight rejected: target node %s is already active on slot %d", op.ID, op.TargetID, op.Slot)
		updateOpStatus(op, OpFailed, "Target node is already active on this slot")
		lease.Release()
		releaseSlot(op.Slot)
		return
	}

	// Verify lease is still valid before spending resources on OpenVPN connect
	sc, _ := sched.Slots.GetSlot(op.Slot)
	if sc != nil && !sc.ValidateLease(lease) {
		log.Printf("[Operation-%s] Lease preempted before candidate start. Aborting.", op.ID)
		updateOpStatus(op, OpFailed, "Operation preempted by newer request")
		lease.Release()
		releaseSlot(op.Slot)
		return
	}

	// 2. CANDIDATE PREPARATION & CONNECTING — In an isolated virtual slot
	updateOpStatus(op, OpConnecting, "")
	candidateSlot := sched.NextTunnelID()
	log.Printf("[Operation-%s] Launching candidate tunnel for node %s on virtual slot %d (active slot %d remains healthy)",
		op.ID, node.IP, candidateSlot, op.Slot)

	ctx, cancel := context.WithTimeout(sched.Context(), 60*time.Second)
	defer cancel()

	tunnel, err := openvpn.StartTunnel(sched.Context(), candidateSlot, &node)
	if err != nil {
		log.Printf("[Operation-%s] Candidate tunnel failed to start: %v. Old active slot %d is unaffected.",
			op.ID, err, op.Slot)
		updateOpStatus(op, OpFailed, fmt.Sprintf("Failed to start candidate tunnel: %v", err))
		_ = scheduler.TransitionNode(database.DB, &node, models.StatusFailed)
		lease.Release()
		releaseSlot(op.Slot)
		return
	}

	// Give OpenVPN time to negotiate and create the tun device
	time.Sleep(5 * time.Second)

	// 3. CANDIDATE VERIFICATION — In isolated candidate routing table
	updateOpStatus(op, OpVerifying, "")
	if err := routing.SetupCandidateRouting(candidateSlot, tunnel.Interface); err != nil {
		log.Printf("[Operation-%s] Candidate routing setup failed: %v. Destroying candidate, old active remains healthy.",
			op.ID, err)
		updateOpStatus(op, OpFailed, fmt.Sprintf("Failed to setup candidate routing: %v", err))
		tunnel.Stop()
		_ = scheduler.TransitionNode(database.DB, &node, models.StatusFailed)
		lease.Release()
		releaseSlot(op.Slot)
		return
	}

	candidateIdent := routing.SlotRoutingIdentity(candidateSlot)
	node.ObservedExitIP = ""
	res := health.VerifyTunnel(ctx, candidateSlot, tunnel.Interface, candidateIdent.TableID, &node)
	if !res.TunnelHealthy || res.Error != nil {
		log.Printf("[Operation-%s] Candidate health verification failed on %s: %v. Old active slot %d remains healthy.",
			op.ID, tunnel.Interface, res.Error, op.Slot)
		updateOpStatus(op, OpFailed, fmt.Sprintf("Candidate health verification failed on dev %s: %v", tunnel.Interface, res.Error))
		routing.ClearCandidateRouting(candidateSlot)
		tunnel.Stop()
		_ = scheduler.TransitionNode(database.DB, &node, models.StatusFailed)
		lease.Release()
		releaseSlot(op.Slot)
		return
	}

	node.ObservedExitIP = res.ObservedExitIP
	database.DB.Model(&node).Update("observed_exit_ip", node.ObservedExitIP)
	exitAdmission, err := sched.EvaluateIPAdmission(ctx, node.ObservedExitIP)
	scheduler.PersistAdmissionResult(&node, exitAdmission)
	if err != nil {
		log.Printf("[Operation-%s] Observed exit %s rejected by admission policy: %v", op.ID, node.ObservedExitIP, err)
		updateOpStatus(op, OpFailed, fmt.Sprintf("Observed exit rejected by admission policy: %v", err))
		routing.ClearCandidateRouting(candidateSlot)
		tunnel.Stop()
		_ = scheduler.TransitionNode(database.DB, &node, models.StatusFailed)
		lease.Release()
		releaseSlot(op.Slot)
		return
	}
	if err := sched.CheckPrefixDiversity(&node, node.ObservedExitIP, op.Slot); err != nil {
		log.Printf("[Operation-%s] Observed exit %s rejected by /24 diversity policy: %v", op.ID, node.ObservedExitIP, err)
		updateOpStatus(op, OpFailed, fmt.Sprintf("Observed exit rejected by IPv4 /24 diversity policy: %v", err))
		routing.ClearCandidateRouting(candidateSlot)
		tunnel.Stop()
		_ = scheduler.TransitionNode(database.DB, &node, models.StatusFailed)
		lease.Release()
		releaseSlot(op.Slot)
		return
	}
	_ = scheduler.TransitionNode(database.DB, &node, models.StatusQualified)
	log.Printf("[Operation-%s] Candidate tunnel %s VERIFIED (observed exit: %s). Proceeding to atomic cutover.",
		op.ID, tunnel.Interface, node.ObservedExitIP)

	// 4. ATOMIC CUTOVER & DRAIN OLD — Candidate is verified READY
	// Check generation lease again to guarantee no concurrent preemption happened
	if sc != nil && !sc.ValidateLease(lease) {
		log.Printf("[Operation-%s] Lease preempted during candidate verification. Aborting candidate.", op.ID)
		routing.ClearCandidateRouting(candidateSlot)
		tunnel.Stop()
		lease.Release()
		releaseSlot(op.Slot)
		updateOpStatus(op, OpFailed, "Operation preempted by newer request")
		return
	}

	// 4a. Update Xray active slots (outside sched.Mu lock!)
	if sched.XraySupervisor != nil {
		if err := sched.XraySupervisor.ActivateSlot(op.Slot); err != nil {
			log.Printf("[Operation-%s] Failed to activate Xray slot %d: %v. Rolling back candidate, old active remains intact.",
				op.ID, op.Slot, err)
			routing.ClearCandidateRouting(candidateSlot)
			tunnel.Stop()
			_ = scheduler.TransitionNode(database.DB, &node, models.StatusFailed)
			updateOpStatus(op, OpFailed, fmt.Sprintf("Failed to activate Xray routing: %v", err))
			lease.Release()
			releaseSlot(op.Slot)
			return
		}
	}

	// 4b. Switch Linux slot routing to point to candidate interface
	if err := routing.SetupSlotRouting(op.Slot, tunnel.Interface); err != nil {
		log.Printf("[Operation-%s] Failed to switch slot routing to %s: %v. Rolling back candidate.",
			op.ID, tunnel.Interface, err)
		routing.ClearCandidateRouting(candidateSlot)
		if hasCurrent && currentActive != nil {
			_ = routing.SetupSlotRouting(op.Slot, currentActive.Interface)
		} else {
			_ = routing.ClearSlotRouting(op.Slot)
			if sched.XraySupervisor != nil {
				_ = sched.XraySupervisor.DrainingSlot(op.Slot)
			}
		}
		tunnel.Stop()
		_ = scheduler.TransitionNode(database.DB, &node, models.StatusFailed)
		updateOpStatus(op, OpFailed, fmt.Sprintf("Failed to switch slot routing: %v", err))
		lease.Release()
		releaseSlot(op.Slot)
		return
	}

	// Clean up temporary candidate routing now that slot routing owns the tunnel
	routing.ClearCandidateRouting(candidateSlot)

	// 4c. Atomic Scheduler State Commit & Move Old Tunnel to DRAINING
	sched.Mu.Lock()
	if err := sched.CheckPrefixDiversityLocked(&node, node.ObservedExitIP, op.Slot); err != nil {
		sched.Mu.Unlock()
		log.Printf("[Operation-%s] Candidate failed final /24 commit check: %v. Rolling back candidate.", op.ID, err)
		if hasCurrent && currentActive != nil {
			_ = routing.SetupSlotRouting(op.Slot, currentActive.Interface)
		} else {
			_ = routing.ClearSlotRouting(op.Slot)
			if sched.XraySupervisor != nil {
				_ = sched.XraySupervisor.DrainingSlot(op.Slot)
			}
		}
		tunnel.Stop()
		_ = scheduler.TransitionNode(database.DB, &node, models.StatusFailed)
		updateOpStatus(op, OpFailed, fmt.Sprintf("Candidate failed final IPv4 /24 commit check: %v", err))
		lease.Release()
		releaseSlot(op.Slot)
		return
	}
	oldTunnel, hadOld := sched.ActiveSlots[op.Slot]
	tunnel.SlotIndex = op.Slot
	sched.ActiveSlots[op.Slot] = tunnel

	if hadOld && oldTunnel != nil && oldTunnel != tunnel {
		log.Printf("[Operation-%s] Confirmed cutover: transitioning previous tunnel %s on slot %d to DRAINING",
			op.ID, oldTunnel.Node.IP, op.Slot)
		if err := sched.DrainReplacedTunnelLocked(op.Slot, oldTunnel); err != nil {
			log.Printf("[Operation-%s] Failed to preserve old tunnel for draining: %v. Rolling slot back.", op.ID, err)
			sched.ActiveSlots[op.Slot] = oldTunnel
			_ = routing.SetupSlotRouting(op.Slot, oldTunnel.Interface)
			sched.Mu.Unlock()
			tunnel.Stop()
			_ = scheduler.TransitionNode(database.DB, &node, models.StatusFailed)
			updateOpStatus(op, OpFailed, fmt.Sprintf("Failed to prepare old tunnel draining: %v", err))
			lease.Release()
			releaseSlot(op.Slot)
			return
		}
	}
	sched.Mu.Unlock()

	_ = scheduler.TransitionNode(database.DB, &node, models.StatusActive)

	if sc != nil {
		sc.Mu.Lock()
		sc.ActiveTunnel = tunnel
		sc.State = scheduler.SlotActive
		sc.OutboundActive = true
		sc.Mu.Unlock()
	}

	lease.Release()
	releaseSlot(op.Slot)

	updateOpStatus(op, OpActive, "")
	log.Printf("[Operation-%s] Transactional manual switch COMPLETED successfully (Node %s ACTIVE on Slot %d).",
		op.ID, node.IP, op.Slot)
}

func releaseSlot(slot int) {
	sched.Mu.Lock()
	sched.ManualOverride[slot] = false
	sched.Mu.Unlock()
}

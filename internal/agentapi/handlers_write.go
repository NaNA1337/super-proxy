package agentapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/NaNA1337/super-proxy/internal/scheduler"
	"github.com/google/uuid"
)

type SwitchRequest struct {
	NodeID string `json:"node_id"`
}

func handleOperationStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		http.Error(w, "Invalid operation ID", http.StatusBadRequest)
		return
	}
	opID := parts[4]

	op, exists := getOperation(opID)
	if !exists {
		http.Error(w, "Operation not found", http.StatusNotFound)
		return
	}

	sendJSON(w, op)
}

func handleSlotAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Protect against OOM attacks: limit body size to 1MB
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 6 || parts[5] != "switch" {
		http.Error(w, "Invalid endpoint. Use /api/v1/slots/{slot}/switch", http.StatusBadRequest)
		return
	}

	slotStr := parts[4]
	slot, err := strconv.Atoi(slotStr)
	if err != nil {
		http.Error(w, "Invalid slot number", http.StatusBadRequest)
		return
	}

	if slot < 0 || slot >= sched.MaxActive {
		http.Error(w, "Slot out of range", http.StatusBadRequest)
		return
	}

	var req SwitchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.NodeID == "" {
		http.Error(w, "node_id is required", http.StatusBadRequest)
		return
	}

	opID := uuid.New().String()

	// ALL validation and reservation performed under scheduler lock to prevent TOCTOU races
	sched.Mu.Lock()

	// 1. Check if slot is already locked by another manual operation
	if sched.ManualOverride[slot] {
		sched.Mu.Unlock()
		http.Error(w, "409 SLOT_BUSY: Slot is currently locked by another manual operation", http.StatusConflict)
		return
	}

	// 2. Verify Node exists
	var node models.Node
	if res := database.DB.Where("id = ?", req.NodeID).First(&node); res.Error != nil {
		sched.Mu.Unlock()
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}

	// 3. Verify state is allowed for manual switch (DISCOVERED, QUALIFIED, or STANDBY)
	if node.Status != models.StatusDiscovered && node.Status != models.StatusStandby && node.Status != models.StatusQualified {
		sched.Mu.Unlock()
		http.Error(w, fmt.Sprintf("Node is not qualified for manual switch. Current status: %s", node.Status), http.StatusConflict)
		return
	}

	// 4. Check if this node is already in use by another slot
	for otherSlot, tunnel := range sched.ActiveSlots {
		if tunnel.Node.ID == req.NodeID {
			sched.Mu.Unlock()
			http.Error(w, fmt.Sprintf("Node already in use by slot %d", otherSlot), http.StatusConflict)
			return
		}
	}

	// 5. Acquire atomic generation lease
	lease, err := sched.Slots.TryAcquireSlot(slot, "manual-switch", opID)
	if err != nil {
		sched.Mu.Unlock()
		http.Error(w, fmt.Sprintf("409 SLOT_BUSY: %v", err), http.StatusConflict)
		return
	}

	// 6. Lock the slot
	sched.ManualOverride[slot] = true
	sched.Mu.Unlock()

	// 7. Reputation check (outside lock since it may take network I/O)
	repRes, err := sched.RepEngine.EvaluateIP(context.Background(), node.IP)
	isConservativeUnknown := sched.RepEngine != nil && sched.RepEngine.FailurePolicy() == "conservative" && repRes != nil && repRes.Status == reputation.StatusUnknown
	if err != nil || repRes == nil || repRes.HardReject || isConservativeUnknown {
		_ = scheduler.TransitionNode(database.DB, &node, models.StatusFailed)
		lease.Release()
		releaseSlot(slot)
		reason := "Node rejected by reputation engine"
		if isConservativeUnknown {
			reason = "Node rejected: reputation UNKNOWN under conservative fail-closed policy"
		}
		http.Error(w, reason, http.StatusForbidden)
		return
	}

	// Create async operation
	op := createSwitchOperation(opID, slot, req.NodeID)

	// Execute state machine in background with generation lease
	go executeManualSwitch(op, lease)

	// Return 202 Accepted
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	sendJSON(w, map[string]string{
		"operation_id": op.ID,
		"status":       "accepted",
	})
}

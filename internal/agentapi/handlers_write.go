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

	// ALL validation under the scheduler lock to prevent TOCTOU races
	sched.Mu.Lock()

	// 1. Check if slot is already locked by another operation
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

	// 3. Verify state is QUALIFIED (DISCOVERED/STANDBY)
	if node.Status != models.StatusDiscovered && node.Status != models.StatusStandby {
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

	// 5. Reserve the slot atomically
	sched.ManualOverride[slot] = true

	// 6. Mark node as being used (prevent another concurrent request from using same node)
	database.DB.Model(&node).Update("status", models.StatusActive)

	sched.Mu.Unlock()

	// 7. Reputation check (outside lock since it may be slow)
	repRes, err := sched.RepEngine.EvaluateIP(context.Background(), node.IP)
	if err != nil || repRes.HardReject {
		database.DB.Model(&node).Update("status", models.StatusFailed)
		releaseSlot(slot)
		http.Error(w, "Node rejected by reputation engine", http.StatusForbidden)
		return
	}

	// Create async operation
	op := createSwitchOperation(slot, req.NodeID)

	// Execute state machine in background
	go executeManualSwitch(op)

	// Return 202 Accepted
	w.WriteHeader(http.StatusAccepted)
	sendJSON(w, map[string]string{
		"operation_id": op.ID,
		"status":       "accepted",
	})
}

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

	// 1. Verify Node exists
	var node models.Node
	if res := database.DB.Where("id = ?", req.NodeID).First(&node); res.Error != nil {
		http.Error(w, "Node not found", http.StatusNotFound)
		return
	}

	// 2. Verify state is QUALIFIED (DISCOVERED/STANDBY)
	if node.Status != "DISCOVERED" && node.Status != "STANDBY" {
		http.Error(w, fmt.Sprintf("Node is not qualified for manual switch. Current status: %s", node.Status), http.StatusConflict)
		return
	}

	// 3. Verify Reputation
	repRes, err := sched.RepEngine.EvaluateIP(context.Background(), node.IP)
	if err != nil || repRes.HardReject {
		http.Error(w, "Node rejected by reputation engine", http.StatusForbidden)
		return
	}

	// Check if already locked by another operation AND reserve it atomically (P1-8)
	sched.Mu.Lock()
	if sched.ManualOverride[slot] {
		sched.Mu.Unlock()
		http.Error(w, "409 SLOT_BUSY: Slot is currently locked by another manual operation", http.StatusConflict)
		return
	}
	sched.ManualOverride[slot] = true
	sched.Mu.Unlock()

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

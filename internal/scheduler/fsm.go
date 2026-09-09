package scheduler

import (
	"fmt"
	"log"
	"sync"

	"github.com/NaNA1337/super-proxy/internal/models"
	"gorm.io/gorm"
)

// AllowedTransitions maps each node status to the set of valid next states.
// Any transition not explicitly listed here is strictly rejected by the FSM.
var AllowedTransitions = map[string]map[string]bool{
	models.StatusNew: {
		models.StatusDiscovered: true,
		models.StatusFailed:     true,
	},
	models.StatusDiscovered: {
		models.StatusReputationChecked: true,
		models.StatusFailed:            true,
		models.StatusStale:             true,
	},
	models.StatusReputationChecked: {
		models.StatusHealthy:   true,
		models.StatusQualified: true,
		models.StatusFailed:    true,
	},
	models.StatusHealthy: {
		models.StatusQualified: true,
		models.StatusFailed:    true,
	},
	models.StatusQualified: {
		models.StatusStandby: true,
		models.StatusActive:  true, // for direct slot assignment after verification
		models.StatusFailed:  true,
	},
	models.StatusStandby: {
		models.StatusActive: true,
		models.StatusFailed: true,
		models.StatusDead:   true,
	},
	models.StatusActive: {
		models.StatusDraining: true,
		models.StatusFailed:   true,
		models.StatusDead:     true,
	},
	models.StatusDraining: {
		models.StatusFailed: true,
		models.StatusDead:   true,
	},
	models.StatusFailed: {
		models.StatusCooldown:   true,
		models.StatusDead:       true,
		models.StatusDiscovered: true, // re-entry after cooldown
	},
	models.StatusCooldown: {
		models.StatusDiscovered: true,
		models.StatusDead:       true,
	},
	models.StatusStale: {
		models.StatusDiscovered: true,
		models.StatusDead:       true,
	},
	models.StatusDead: {
		models.StatusDiscovered: true, // manual or admin revival
	},
}

var fsmMu sync.Mutex

// CanTransition checks if moving from current to target is allowed by the FSM.
func CanTransition(current, target string) bool {
	if current == target {
		return true // No-op transition
	}
	nextStates, exists := AllowedTransitions[current]
	if !exists {
		return false
	}
	return nextStates[target]
}

// TransitionNode transitions a node to targetStatus with validation and database persistence.
func TransitionNode(db *gorm.DB, node *models.Node, targetStatus string) error {
	fsmMu.Lock()
	defer fsmMu.Unlock()

	currentStatus := node.Status
	if currentStatus == "" {
		currentStatus = models.StatusNew
	}

	if !CanTransition(currentStatus, targetStatus) {
		return fmt.Errorf("FSM_INVALID_TRANSITION: node %s cannot transition from %s to %s",
			node.ID, currentStatus, targetStatus)
	}

	updates := map[string]interface{}{
		"status": targetStatus,
	}

	if targetStatus == models.StatusFailed {
		newFailCount := node.FailCount + 1
		updates["fail_count"] = newFailCount
		node.FailCount = newFailCount
		if newFailCount >= 3 {
			targetStatus = models.StatusDead
			updates["status"] = models.StatusDead
		}
	}

	if db != nil {
		if err := db.Model(node).Updates(updates).Error; err != nil {
			return fmt.Errorf("failed to persist state transition to DB: %w", err)
		}
	}

	prev := node.Status
	node.Status = targetStatus
	log.Printf("[FSM] Node %s (%s) transition: %s -> %s (fails=%d)",
		node.ID, node.IP, prev, targetStatus, node.FailCount)
	return nil
}

// TransitionNodeDirect updates status directly on in-memory node struct with FSM validation (used when DB is unavailable)
func TransitionNodeDirect(node *models.Node, targetStatus string) error {
	return TransitionNode(nil, node, targetStatus)
}

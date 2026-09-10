package scheduler

import (
	"sync"
	"testing"

	"github.com/NaNA1337/super-proxy/internal/discovery"
	"github.com/NaNA1337/super-proxy/internal/models"
)

func TestFSM_ValidTransitions(t *testing.T) {
	node := &models.Node{
		ID:     "node-test-1",
		IP:     "192.168.1.100",
		Status: models.StatusNew,
	}

	chain := []string{
		models.StatusDiscovered,
		models.StatusReputationChecked,
		models.StatusQualified,
		models.StatusStandby,
		models.StatusActive,
		models.StatusDraining,
		models.StatusFailed,
		models.StatusCooldown,
		models.StatusDiscovered,
	}

	for _, target := range chain {
		err := TransitionNodeDirect(node, target)
		if err != nil {
			t.Fatalf("Expected valid transition to %s, got error: %v", target, err)
		}
		if node.Status != target {
			t.Errorf("Expected status %s, got %s", target, node.Status)
		}
	}
}

func TestFSM_InvalidTransitions(t *testing.T) {
	invalidCases := []struct {
		from string
		to   string
	}{
		{models.StatusDiscovered, models.StatusActive},   // Bypass qualification
		{models.StatusDiscovered, models.StatusStandby},  // Bypass reputation
		{models.StatusFailed, models.StatusActive},       // Unqualified recovery
		{models.StatusDraining, models.StatusActive},     // Cannot reactivate draining
		{models.StatusNew, models.StatusActive},          // Immediate jump
		{models.StatusDead, models.StatusActive},         // Dead node to active
	}

	for _, tc := range invalidCases {
		t.Run(tc.from+"->"+tc.to, func(t *testing.T) {
			node := &models.Node{
				ID:     "node-invalid-test",
				IP:     "192.168.1.101",
				Status: tc.from,
			}
			err := TransitionNodeDirect(node, tc.to)
			if err == nil {
				t.Errorf("Expected transition %s -> %s to fail, but it succeeded", tc.from, tc.to)
			}
		})
	}
}

func TestFSM_FailCountAndDeadTransition(t *testing.T) {
	node := &models.Node{
		ID:        "node-fail-test",
		IP:        "192.168.1.102",
		Status:    models.StatusActive,
		FailCount: 0,
	}

	// 1st failure
	_ = TransitionNodeDirect(node, models.StatusDraining)
	_ = TransitionNodeDirect(node, models.StatusFailed)
	if node.Status != models.StatusFailed || node.FailCount != 1 {
		t.Fatalf("Expected FAILED with count 1, got %s, count %d", node.Status, node.FailCount)
	}

	// Cooldown and re-enter
	_ = TransitionNodeDirect(node, models.StatusCooldown)
	_ = TransitionNodeDirect(node, models.StatusDiscovered)
	_ = TransitionNodeDirect(node, models.StatusReputationChecked)
	_ = TransitionNodeDirect(node, models.StatusQualified)
	_ = TransitionNodeDirect(node, models.StatusActive)

	// 2nd failure
	_ = TransitionNodeDirect(node, models.StatusDraining)
	_ = TransitionNodeDirect(node, models.StatusFailed)
	if node.Status != models.StatusFailed || node.FailCount != 2 {
		t.Fatalf("Expected FAILED with count 2, got %s, count %d", node.Status, node.FailCount)
	}

	// Cooldown and re-enter
	_ = TransitionNodeDirect(node, models.StatusCooldown)
	_ = TransitionNodeDirect(node, models.StatusDiscovered)
	_ = TransitionNodeDirect(node, models.StatusReputationChecked)
	_ = TransitionNodeDirect(node, models.StatusQualified)
	_ = TransitionNodeDirect(node, models.StatusActive)

	// 3rd failure -> MUST transition to DEAD
	_ = TransitionNodeDirect(node, models.StatusDraining)
	_ = TransitionNodeDirect(node, models.StatusFailed)
	if node.Status != models.StatusDead || node.FailCount != 3 {
		t.Fatalf("Expected DEAD with count 3, got %s, count %d", node.Status, node.FailCount)
	}
}

func TestFSM_ConcurrentTransitions(t *testing.T) {
	node := &models.Node{
		ID:     "node-concurrent-test",
		IP:     "192.168.1.103",
		Status: models.StatusDiscovered,
	}

	var wg sync.WaitGroup
	workers := 50

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			if id%2 == 0 {
				_ = TransitionNodeDirect(node, models.StatusReputationChecked)
			} else {
				// Invalid jump, must be rejected
				_ = TransitionNodeDirect(node, models.StatusActive)
			}
		}(i)
	}

	wg.Wait()

	// Final status must be valid
	if node.Status != models.StatusDiscovered && node.Status != models.StatusReputationChecked {
		t.Errorf("Unexpected final status under race: %s", node.Status)
	}
}

func TestFSM_SecretEvictedOnFailedAndDead(t *testing.T) {
	node := &models.Node{
		ID:     "node-secret-evict-fsm",
		IP:     "192.168.10.99",
		Status: models.StatusDiscovered,
	}

	// Store secret in memory
	discovery.SetOVPNSecret(node.ID, "raw-secret-123")
	sec, ok := discovery.GetOVPNSecret(node.ID)
	if !ok || sec != "raw-secret-123" {
		t.Fatalf("expected secret to be present in cache")
	}

	// Transition to Failed -> secret MUST be evicted
	if err := TransitionNodeDirect(node, models.StatusFailed); err != nil {
		t.Fatalf("unexpected transition error: %v", err)
	}
	_, okAfterFail := discovery.GetOVPNSecret(node.ID)
	if okAfterFail {
		t.Fatalf("SECURITY VIOLATION: secret remained in cache after node transitioned to FAILED")
	}

	// Re-add secret and test Dead transition
	discovery.SetOVPNSecret(node.ID, "raw-secret-456")
	node.Status = models.StatusDraining
	node.FailCount = 2
	if err := TransitionNodeDirect(node, models.StatusFailed); err != nil {
		t.Fatalf("unexpected transition error: %v", err)
	}
	if node.Status != models.StatusDead {
		t.Fatalf("expected status Dead, got %s", node.Status)
	}
	_, okAfterDead := discovery.GetOVPNSecret(node.ID)
	if okAfterDead {
		t.Fatalf("SECURITY VIOLATION: secret remained in cache after node transitioned to DEAD")
	}
}


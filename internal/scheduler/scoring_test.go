package scheduler

import (
	"testing"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/models"
)

func TestScoringEngine_Comprehensive(t *testing.T) {
	cfg := config.ScoringConfig{
		VPNPenalty:     5,
		TorPenalty:     50,
		HostingPenalty: 10,
		FailurePenalty: 30,
		SpeedWeight:    1.0,
		LatencyWeight:  0.5,
	}
	engine := NewScoringEngine(cfg)

	// Case 1: Clean high-performance primary node
	nodePrimary := &models.Node{
		ID:    "node-primary",
		IP:    "198.51.100.10",
		Score: 100,
		Performance: models.PerformanceMetrics{
			DownloadSpeed: 50_000_000, // 50 Mbps -> +50
			RTT:           50,         // (200 - 50) * 0.5 = +75
		},
	}
	resPrimary := engine.EvaluateNode(nodePrimary, true, 0, "")
	if !resPrimary.Allowed {
		t.Fatalf("Expected primary clean node to be allowed")
	}
	expectedScore := 100 + 50 + 50 + 75 // 275
	if resPrimary.FinalScore != expectedScore {
		t.Fatalf("Expected score %d, got %d. Explanation: %s", expectedScore, resPrimary.FinalScore, resPrimary.Explanation)
	}

	// Case 2: Hosting and VPN soft penalties
	nodeVPN := &models.Node{
		ID:    "node-vpn",
		IP:    "198.51.100.11",
		Score: 100,
		NetClass: models.NetworkClass{
			IsHosting: true,
			IsVPN:     true,
		},
	}
	resVPN := engine.EvaluateNode(nodeVPN, false, 0, "")
	if !resVPN.Allowed {
		t.Fatalf("VPN/Hosting node should still be allowed with soft penalty")
	}
	expectedVPNScore := 100 - 10 - 5 // 85
	if resVPN.FinalScore != expectedVPNScore {
		t.Fatalf("Expected score %d, got %d", expectedVPNScore, resVPN.FinalScore)
	}

	// Case 3: Blacklisted node hard reject
	nodeBlacklisted := &models.Node{
		ID:    "node-bad",
		IP:    "198.51.100.12",
		Score: 500,
		Reputation: models.ReputationMetrics{
			IsBlacklisted: true,
		},
	}
	resBad := engine.EvaluateNode(nodeBlacklisted, true, 0, "")
	if resBad.Allowed {
		t.Fatalf("Blacklisted node MUST NOT be allowed")
	}

	// Case 4: Repeated failures penalty
	nodeFails := &models.Node{
		ID:        "node-fails",
		IP:        "198.51.100.13",
		Score:     50,
		FailCount: 3, // 3 * 30 = 90 penalty
	}
	resFails := engine.EvaluateNode(nodeFails, false, 0, "")
	expectedFailScore := 50 - 90 // -40
	if resFails.FinalScore != expectedFailScore {
		t.Fatalf("Expected score %d, got %d", expectedFailScore, resFails.FinalScore)
	}
}

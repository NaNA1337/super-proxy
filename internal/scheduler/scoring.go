package scheduler

import (
	"fmt"
	"strings"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/models"
)

// ScoringResult encapsulates the evaluated score and transparent audit trail for scheduler decisions.
type ScoringResult struct {
	FinalScore   int
	Allowed      bool
	Explanation  string
	Explanations []string
}

// ScoringEngine unifies all node candidate weighting and filtering.
type ScoringEngine struct {
	cfg config.ScoringConfig
}

// NewScoringEngine creates a unified scoring engine from configuration.
func NewScoringEngine(cfg config.ScoringConfig) *ScoringEngine {
	// Set safe defaults if not configured
	if cfg.VPNPenalty <= 0 {
		cfg.VPNPenalty = 5
	}
	if cfg.TorPenalty <= 0 {
		cfg.TorPenalty = 50
	}
	if cfg.HostingPenalty <= 0 {
		cfg.HostingPenalty = 10
	}
	if cfg.PrefixBadLimit <= 0 {
		cfg.PrefixBadLimit = 3
	}
	if cfg.PrefixPenalty <= 0 {
		cfg.PrefixPenalty = 20
	}
	if cfg.FailurePenalty <= 0 {
		cfg.FailurePenalty = 30
	}
	if cfg.SpeedWeight <= 0 {
		cfg.SpeedWeight = 1.0
	}
	if cfg.LatencyWeight <= 0 {
		cfg.LatencyWeight = 0.5
	}
	return &ScoringEngine{cfg: cfg}
}

// EvaluateNode computes the final score and generates a full decision explanation.
func (s *ScoringEngine) EvaluateNode(node *models.Node, isPrimaryRegion bool, prefixPenalty int, prefixReason string) ScoringResult {
	var reasons []string

	// Hard Reject checks
	if node.Reputation.IsBlacklisted {
		return ScoringResult{
			FinalScore:  -9999,
			Allowed:     false,
			Explanation: fmt.Sprintf("Node %s (%s) REJECTED: blacklisted by reputation provider", node.ID, node.IP),
			Explanations: []string{"Blacklisted by reputation provider"},
		}
	}

	// 1. Base VPN Gate score
	vpnGateScore := node.Score
	reasons = append(reasons, fmt.Sprintf("VPNGate base: %d", vpnGateScore))

	// 2. Region score (Primary region receives priority bonus)
	regionBonus := 0
	if isPrimaryRegion {
		regionBonus = 50
		reasons = append(reasons, "Primary region bonus: +50")
	} else {
		reasons = append(reasons, "Fallback region: +0")
	}

	// 3. Performance: Speed score (1 point per Mbps download)
	speedBonus := 0
	if node.Performance.DownloadSpeed > 0 {
		speedMbps := float64(node.Performance.DownloadSpeed) / 1_000_000.0
		speedBonus = int(speedMbps * s.cfg.SpeedWeight)
		if speedBonus > 200 {
			speedBonus = 200 // Cap speed bonus
		}
		reasons = append(reasons, fmt.Sprintf("Speed bonus: +%d (%.1f Mbps)", speedBonus, speedMbps))
	}

	// 4. Performance: Latency score (Bonus for low RTT)
	latencyBonus := 0
	if node.Performance.RTT > 0 {
		if node.Performance.RTT < 200 {
			latencyBonus = int(float64(200-node.Performance.RTT) * s.cfg.LatencyWeight)
			reasons = append(reasons, fmt.Sprintf("Latency bonus: +%d (RTT %dms)", latencyBonus, node.Performance.RTT))
		} else {
			reasons = append(reasons, fmt.Sprintf("High latency: RTT %dms", node.Performance.RTT))
		}
	}

	// 5. Reputation penalty
	repPenalty := node.Reputation.FraudScore
	if repPenalty > 0 {
		reasons = append(reasons, fmt.Sprintf("Reputation fraud penalty: -%d", repPenalty))
	}

	// 6. Prefix Intelligence penalty
	if prefixPenalty > 0 {
		reasons = append(reasons, fmt.Sprintf("Prefix risk penalty: -%d (%s)", prefixPenalty, prefixReason))
	}

	// 7. Network Intelligence penalties
	netPenalty := 0
	if node.NetClass.IsHosting {
		netPenalty += s.cfg.HostingPenalty
		reasons = append(reasons, fmt.Sprintf("Hosting datacenter penalty: -%d", s.cfg.HostingPenalty))
	}
	if node.NetClass.IsVPN {
		netPenalty += s.cfg.VPNPenalty
		reasons = append(reasons, fmt.Sprintf("Commercial VPN penalty: -%d", s.cfg.VPNPenalty))
	}
	if node.NetClass.IsProxy {
		netPenalty += s.cfg.VPNPenalty
		reasons = append(reasons, fmt.Sprintf("Public proxy penalty: -%d", s.cfg.VPNPenalty))
	}
	if node.NetClass.IsTor {
		netPenalty += s.cfg.TorPenalty
		reasons = append(reasons, fmt.Sprintf("Tor exit penalty: -%d", s.cfg.TorPenalty))
	}

	// 8. Historical failure penalty
	failPenalty := node.FailCount * s.cfg.FailurePenalty
	if failPenalty > 0 {
		reasons = append(reasons, fmt.Sprintf("Failure history penalty: -%d (fails=%d)", failPenalty, node.FailCount))
	}

	finalScore := vpnGateScore + regionBonus + speedBonus + latencyBonus - repPenalty - prefixPenalty - netPenalty - failPenalty

	allowed := finalScore >= -100
	statusStr := "ACCEPTED"
	if !allowed {
		statusStr = "REJECTED (Score below threshold -100)"
	}

	explanation := fmt.Sprintf("Node %s (%s) %s: FinalScore=%d [%s]",
		node.ID, node.IP, statusStr, finalScore, strings.Join(reasons, "; "))

	return ScoringResult{
		FinalScore:   finalScore,
		Allowed:      allowed,
		Explanation:  explanation,
		Explanations: reasons,
	}
}

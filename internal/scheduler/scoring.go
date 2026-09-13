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
	if cfg.ResidentialBonus <= 0 {
		cfg.ResidentialBonus = 40
	}
	if cfg.BusinessBonus <= 0 {
		cfg.BusinessBonus = 20
	}
	if cfg.WirelessBonus <= 0 {
		cfg.WirelessBonus = 25
	}
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
	return s.EvaluateNodeWithASN(node, isPrimaryRegion, prefixPenalty, prefixReason, 0, "")
}

// EvaluateNodeWithASN computes the final score incorporating ASN historical profiling and packet loss.
func (s *ScoringEngine) EvaluateNodeWithASN(node *models.Node, isPrimaryRegion bool, prefixPenalty int, prefixReason string, asnPenalty int, asnReason string) ScoringResult {
	var reasons []string

	// Hard Reject checks
	if node.Reputation.IsBlacklisted {
		return ScoringResult{
			FinalScore:   -9999,
			Allowed:      false,
			Explanation:  fmt.Sprintf("Node %s (%s) REJECTED: blacklisted by reputation provider", node.ID, node.IP),
			Explanations: []string{"Blacklisted by reputation provider"},
		}
	}
	if node.NetClass.IsHosting || node.NetClass.IsVPN || node.NetClass.IsProxy || node.NetClass.IsTor {
		traits := make([]string, 0, 4)
		if node.NetClass.IsHosting {
			traits = append(traits, "hosting/datacenter")
		}
		if node.NetClass.IsVPN {
			traits = append(traits, "VPN")
		}
		if node.NetClass.IsProxy {
			traits = append(traits, "public proxy")
		}
		if node.NetClass.IsTor {
			traits = append(traits, "Tor")
		}
		return ScoringResult{
			FinalScore:   -9999,
			Allowed:      false,
			Explanation:  fmt.Sprintf("Node %s (%s) REJECTED: prohibited network traits: %s", node.ID, node.IP, strings.Join(traits, ", ")),
			Explanations: []string{"Prohibited network traits: " + strings.Join(traits, ", ")},
		}
	}

	// VPN Gate's self-reported source score is deliberately excluded. Candidate
	// quality begins with independently resolved network allocation type.
	networkBonus := 0
	switch strings.ToLower(strings.TrimSpace(node.NetClass.NetworkType)) {
	case "residential", "broadband", "isp":
		networkBonus = s.cfg.ResidentialBonus
		reasons = append(reasons, fmt.Sprintf("Residential/broadband network bonus: +%d", networkBonus))
	case "wireless", "mobile":
		networkBonus = s.cfg.WirelessBonus
		reasons = append(reasons, fmt.Sprintf("Wireless/mobile network bonus: +%d", networkBonus))
	case "business", "corporate":
		networkBonus = s.cfg.BusinessBonus
		reasons = append(reasons, fmt.Sprintf("Business network bonus: +%d", networkBonus))
	default:
		reasons = append(reasons, "Unknown network allocation: +0")
	}

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
	speedMbps := 0.0
	if node.Performance.DownloadSpeed > 0 {
		speedMbps = float64(node.Performance.DownloadSpeed) / 1_000_000.0
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

	// 5. Packet Loss penalty
	lossPenalty := 0
	if node.Performance.PacketLoss > 2.0 {
		lossPenalty = int(node.Performance.PacketLoss * 2)
		reasons = append(reasons, fmt.Sprintf("Packet loss penalty: -%d (%.1f%% loss)", lossPenalty, node.Performance.PacketLoss))
	}

	// 6. Reputation penalty
	repPenalty := node.Reputation.FraudScore
	if repPenalty > 0 {
		reasons = append(reasons, fmt.Sprintf("Reputation fraud penalty: -%d", repPenalty))
	}

	// 7. Prefix Intelligence penalty
	if prefixPenalty > 0 {
		reasons = append(reasons, fmt.Sprintf("Prefix risk penalty: -%d (%s)", prefixPenalty, prefixReason))
	}

	// 8. ASN / ISP risk penalty
	if asnPenalty > 0 {
		reasons = append(reasons, fmt.Sprintf("ASN risk penalty: -%d (%s)", asnPenalty, asnReason))
	}

	// 9. Network Intelligence penalties. Prohibited boolean traits are rejected above;
	// penalties remain for provider-specific scores that do not assert those traits.
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

	// Connection failures remain diagnostic history only. Public VPN endpoints
	// are volatile, so an old handshake failure must never lower admission score
	// or permanently remove a newly rediscovered endpoint from consideration.
	finalScore := networkBonus + regionBonus + speedBonus + latencyBonus - lossPenalty - repPenalty - prefixPenalty - asnPenalty - netPenalty

	allowed := finalScore >= -100
	var explanation string
	if allowed {
		explanation = fmt.Sprintf("Node %s (%s) QUALIFIED: FinalScore=%d (rep=%s, ASN=%s, RTT=%dms, speed=%.1fMbps, loss=%.1f%%) [%s]",
			node.ID, node.IP, finalScore, node.Reputation.Status, node.NetClass.ASN, node.Performance.RTT, speedMbps, node.Performance.PacketLoss, strings.Join(reasons, "; "))
	} else {
		explanation = fmt.Sprintf("Node %s (%s) REJECTED (Score below threshold -100): FinalScore=%d [%s]",
			node.ID, node.IP, finalScore, strings.Join(reasons, "; "))
	}

	return ScoringResult{
		FinalScore:   finalScore,
		Allowed:      allowed,
		Explanation:  explanation,
		Explanations: reasons,
	}
}

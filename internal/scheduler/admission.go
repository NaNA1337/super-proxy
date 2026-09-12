package scheduler

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/reputation"
)

// EvaluateIPAdmission applies the non-negotiable network reputation policy.
// A score can never override a VPN, proxy, Tor, hosting, blacklist, or UNKNOWN verdict.
func (s *Scheduler) EvaluateIPAdmission(ctx context.Context, ip string) (*reputation.Result, error) {
	if net.ParseIP(strings.TrimSpace(ip)) == nil {
		return nil, fmt.Errorf("invalid candidate IP %q", ip)
	}
	if s.RepEngine == nil {
		return nil, fmt.Errorf("reputation engine is unavailable")
	}

	result, err := s.RepEngine.EvaluateIP(ctx, ip)
	if err != nil {
		return nil, fmt.Errorf("reputation lookup failed: %w", err)
	}
	if result == nil {
		return nil, fmt.Errorf("reputation lookup returned no result")
	}
	if result.HardReject {
		return result, fmt.Errorf("reputation provider hard-rejected %s: %s", ip, result.ProviderReason)
	}
	if result.NetworkInfo.IsHosting || result.NetworkInfo.IsVPN || result.NetworkInfo.IsProxy || result.NetworkInfo.IsTor {
		traits := prohibitedTraits(result.NetworkInfo)
		return result, fmt.Errorf("prohibited network traits for %s: %s", ip, strings.Join(traits, ", "))
	}
	if result.Status == reputation.StatusUnknown && s.RepEngine.FailurePolicy() == "conservative" {
		return result, fmt.Errorf("reputation UNKNOWN under conservative policy for %s: %s", ip, result.ProviderReason)
	}
	return result, nil
}

func prohibitedTraits(info models.NetworkClass) []string {
	traits := make([]string, 0, 4)
	if info.IsHosting {
		traits = append(traits, "hosting/datacenter")
	}
	if info.IsVPN {
		traits = append(traits, "VPN")
	}
	if info.IsProxy {
		traits = append(traits, "public proxy")
	}
	if info.IsTor {
		traits = append(traits, "Tor")
	}
	return traits
}

// PersistAdmissionResult stores the verdict displayed by the Agent API and Manager.
func PersistAdmissionResult(node *models.Node, result *reputation.Result) {
	if node == nil || result == nil {
		return
	}
	node.Reputation.Status = string(result.Status)
	node.Reputation.IsBlacklisted = result.HardReject
	node.Reputation.FraudScore = result.ScorePenalty
	node.Reputation.ProviderName = "multi-provider"
	node.Reputation.Details = result.ProviderReason
	node.NetClass = result.NetworkInfo
	if database.DB != nil {
		database.DB.Model(node).Updates(map[string]interface{}{
			"rep_status":         node.Reputation.Status,
			"rep_is_blacklisted": node.Reputation.IsBlacklisted,
			"rep_fraud_score":    node.Reputation.FraudScore,
			"rep_provider_name":  node.Reputation.ProviderName,
			"rep_details":        node.Reputation.Details,
			"net_asn":            node.NetClass.ASN,
			"net_isp":            node.NetClass.ISP,
			"net_organization":   node.NetClass.Organization,
			"net_network_type":   node.NetClass.NetworkType,
			"net_is_vpn":         node.NetClass.IsVPN,
			"net_is_proxy":       node.NetClass.IsProxy,
			"net_is_tor":         node.NetClass.IsTor,
			"net_is_hosting":     node.NetClass.IsHosting,
		})
	}
}

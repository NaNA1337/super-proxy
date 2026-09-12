package discovery

import (
	"context"
	"sync"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/reputation"
)

type AdmissionFunc func(context.Context, *models.Node) (*reputation.Result, error)
type CandidateScoreFunc func(*models.Node) int

type VettingSummary struct {
	Accepted int
	Rejected int
}

// VetNodes completes ASN and reputation admission for an entire discovery
// response before any of its nodes are persisted as switchable candidates.
func VetNodes(ctx context.Context, nodes []models.Node, concurrency int, admit AdmissionFunc, score CandidateScoreFunc) ([]models.Node, VettingSummary) {
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > 32 {
		concurrency = 32
	}
	if admit == nil {
		for i := range nodes {
			nodes[i].Status = models.StatusFailed
			nodes[i].Reputation.Status = string(reputation.StatusUnknown)
			nodes[i].Reputation.Details = "reputation admission function is unavailable"
			nodes[i].LastError = nodes[i].Reputation.Details
			nodes[i].LastFailureAt = time.Now()
			DeleteOVPNSecret(nodes[i].ID)
		}
		return nodes, VettingSummary{Rejected: len(nodes)}
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				result, err := admit(ctx, &nodes[i])
				applyAdmissionResult(&nodes[i], result)
				if err != nil {
					nodes[i].Status = models.StatusFailed
					nodes[i].LastError = "discovery reputation admission: " + err.Error()
					nodes[i].LastFailureAt = time.Now()
					if nodes[i].Reputation.Details == "" {
						nodes[i].Reputation.Status = string(reputation.StatusUnknown)
						nodes[i].Reputation.Details = err.Error()
					}
					DeleteOVPNSecret(nodes[i].ID)
					continue
				}
				nodes[i].Status = models.StatusReputationChecked
				nodes[i].LastError = ""
				nodes[i].LastFailureAt = time.Time{}
				if score != nil {
					nodes[i].Score = score(&nodes[i])
				} else {
					nodes[i].Score = 0
				}
			}
		}()
	}
	for i := range nodes {
		select {
		case jobs <- i:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			for j := i; j < len(nodes); j++ {
				nodes[j].Status = models.StatusFailed
				nodes[j].Reputation.Status = string(reputation.StatusUnknown)
				nodes[j].Reputation.Details = ctx.Err().Error()
				nodes[j].LastError = "discovery reputation admission: " + ctx.Err().Error()
				nodes[j].LastFailureAt = time.Now()
				DeleteOVPNSecret(nodes[j].ID)
			}
			return nodes, summarizeVetting(nodes)
		}
	}
	close(jobs)
	wg.Wait()
	return nodes, summarizeVetting(nodes)
}

func applyAdmissionResult(node *models.Node, result *reputation.Result) {
	if node == nil || result == nil {
		return
	}
	node.Reputation.Status = string(result.Status)
	node.Reputation.IsBlacklisted = result.HardReject
	node.Reputation.FraudScore = result.ScorePenalty
	node.Reputation.ProviderName = "multi-provider"
	node.Reputation.Details = result.ProviderReason
	node.NetClass = result.NetworkInfo
}

func summarizeVetting(nodes []models.Node) VettingSummary {
	var summary VettingSummary
	for i := range nodes {
		if nodes[i].Status == models.StatusReputationChecked {
			summary.Accepted++
		} else {
			summary.Rejected++
		}
	}
	return summary
}

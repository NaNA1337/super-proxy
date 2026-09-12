package scheduler

import (
	"fmt"
	"log"
	"strings"

	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/discovery"
	"github.com/NaNA1337/super-proxy/internal/models"
	"gorm.io/gorm"
)

// CandidateSelectionResult contains the selected node and region audit details.
type CandidateSelectionResult struct {
	Node              *models.Node
	QualifiedCapacity int
	PrimaryCount      int // Backward-compatible alias for QualifiedCapacity
	Required          int
	FallbackEnabled   bool
	IsFallbackNode    bool
}

// Eligible statuses that count toward primary qualified capacity
// (QUALIFIED + STANDBY + usable ACTIVE/HEALTHY; explicitly EXCLUDES DISCOVERED candidates
// which have not yet passed reputation, connection, health, or speed qualification)
var qualifiedCapacityStatuses = []string{
	models.StatusActive,
	models.StatusStandby,
	models.StatusQualified,
	models.StatusHealthy,
}

// Unassigned candidate statuses available to be selected for standby/active promotion
var candidateSelectStatuses = []string{
	models.StatusQualified,
	models.StatusHealthy,
	models.StatusDiscovered,
}

// SelectNextCandidate audits eligible candidates in the database and returns the best node.
// GUARANTEES:
// 1. If primary qualified capacity >= required (MaxActive + MaxStandby), Fallback is strictly disabled.
// 2. High-score Fallback nodes can NEVER bypass Primary candidates when Primary >= required.
// 3. Even when Fallback is enabled (Primary < required), any available Primary nodes are exhausted first.
// 4. Detailed audit explanations are logged for full observability.
func (s *Scheduler) SelectNextCandidate() (*CandidateSelectionResult, error) {
	required := s.MaxActive + s.MaxStandby
	if required <= 0 {
		required = 5
	}

	primaryRegion := strings.ToUpper(strings.TrimSpace(s.RegionConfig.Primary))

	// 1. Count usable qualified capacity in Primary. Running ACTIVE/STANDBY
	// tunnels remain capacity; unassigned QUALIFIED/HEALTHY nodes require a
	// current runtime credential before they count.
	var qualifiedNodes []models.Node
	primaryQuery := database.DB.Model(&models.Node{}).
		Where("status IN (?) AND fail_count < 3", qualifiedCapacityStatuses)
	if primaryRegion != "" {
		primaryQuery = primaryQuery.Where("UPPER(country) = ?", primaryRegion)
	}
	if err := primaryQuery.Find(&qualifiedNodes).Error; err != nil {
		return nil, fmt.Errorf("failed to load primary qualified capacity from DB: %w", err)
	}
	qualifiedCapacity := 0
	for i := range qualifiedNodes {
		if qualifiedNodes[i].Status == models.StatusActive || qualifiedNodes[i].Status == models.StatusStandby {
			qualifiedCapacity++
			continue
		}
		if _, ok := discovery.GetOVPNSecret(qualifiedNodes[i].ID); ok {
			qualifiedCapacity++
		}
	}

	fallbackEnabled := qualifiedCapacity < required
	log.Printf("[Scheduler] Region capacity audit: primary=%s, qualified_capacity=%d, required=%d, fallback enabled=%v",
		primaryRegion, qualifiedCapacity, required, fallbackEnabled)

	res := &CandidateSelectionResult{
		QualifiedCapacity: qualifiedCapacity,
		PrimaryCount:      qualifiedCapacity,
		Required:          required,
		FallbackEnabled:   fallbackEnabled,
	}

	// Select the highest-scoring candidate that does not duplicate an active or
	// standby endpoint/egress /24.
	pickDiverseCandidate := func(q *gorm.DB) (*models.Node, error) {
		var candidates []models.Node
		if err := q.Order("CASE WHEN status = 'QUALIFIED' THEN 1 WHEN status = 'HEALTHY' THEN 2 ELSE 3 END, score DESC").
			Limit(512).Find(&candidates).Error; err != nil {
			return nil, err
		}
		for i := range candidates {
			if _, ok := discovery.GetOVPNSecret(candidates[i].ID); !ok {
				log.Printf("[Scheduler] Skipping candidate %s: OpenVPN credentials are not available in memory", candidates[i].IP)
				continue
			}
			if err := s.CheckPrefixDiversity(&candidates[i], "", -1); err != nil {
				log.Printf("[Scheduler] Skipping /24-duplicate candidate %s: %v", candidates[i].IP, err)
				continue
			}
			return &candidates[i], nil
		}
		return nil, gorm.ErrRecordNotFound
	}

	queryBestCandidate := func(countryFilter string) (*models.Node, error) {
		q := database.DB.Where("status IN (?) AND fail_count < 3", candidateSelectStatuses)
		if countryFilter != "" {
			q = q.Where("UPPER(country) = ?", countryFilter)
		}
		return pickDiverseCandidate(q)
	}

	// Case 1: Primary qualified capacity meets or exceeds required threshold -> Fallback is FORBIDDEN
	if !fallbackEnabled {
		node, err := queryBestCandidate(primaryRegion)
		if err != nil {
			return nil, fmt.Errorf("error selecting primary candidate: %w", err)
		}
		res.Node = node
		res.IsFallbackNode = false
		log.Printf("[Scheduler] Candidate selected from Primary (%s, status=%s, score=%d)", node.Country, node.Status, node.Score)
		return res, nil
	}

	// Case 2: Fallback is enabled because Primary < required.
	// We STILL attempt to pick remaining Primary nodes first before falling back!
	if node, err := queryBestCandidate(primaryRegion); err == nil {
		res.Node = node
		res.IsFallbackNode = false
		log.Printf("[Scheduler] Candidate selected from Primary (%s, status=%s, score=%d) while fallback open", node.Country, node.Status, node.Score)
		return res, nil
	}

	// Primary region candidates completely exhausted; select from Fallback regions
	var fallbackUpper []string
	for _, fb := range s.RegionConfig.Fallback {
		trimmed := strings.ToUpper(strings.TrimSpace(fb))
		if trimmed != "" {
			fallbackUpper = append(fallbackUpper, trimmed)
		}
	}

	if len(fallbackUpper) == 0 {
		return nil, fmt.Errorf("primary candidates exhausted and no fallback regions configured")
	}

	fbNode, err := pickDiverseCandidate(database.DB.Where("status IN (?) AND fail_count < 3 AND UPPER(country) IN ?",
		candidateSelectStatuses, fallbackUpper))
	if err != nil {
		return nil, fmt.Errorf("no candidates found in fallback regions: %w", err)
	}

	res.Node = fbNode
	res.IsFallbackNode = true
	log.Printf("[Scheduler] Primary candidates exhausted (%d < %d). Using Fallback node %s (%s, status=%s, score=%d)",
		qualifiedCapacity, required, fbNode.IP, fbNode.Country, fbNode.Status, fbNode.Score)
	return res, nil
}

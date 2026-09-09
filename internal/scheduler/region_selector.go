package scheduler

import (
	"fmt"
	"log"
	"strings"

	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/models"
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
var qualifiedCapacityStatuses = []string{
	models.StatusActive,
	models.StatusStandby,
	models.StatusQualified,
	models.StatusHealthy,
	models.StatusDiscovered,
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

	// 1. Count total qualified capacity in Primary region (active, standby, qualified, healthy, discovered)
	var qualifiedCapacity int64
	primaryQuery := database.DB.Model(&models.Node{}).
		Where("status IN (?) AND fail_count < 3", qualifiedCapacityStatuses)
	if primaryRegion != "" {
		primaryQuery = primaryQuery.Where("UPPER(country) = ?", primaryRegion)
	}
	if err := primaryQuery.Count(&qualifiedCapacity).Error; err != nil {
		return nil, fmt.Errorf("failed to count primary qualified capacity in DB: %w", err)
	}

	fallbackEnabled := int(qualifiedCapacity) < required
	log.Printf("[Scheduler] Region capacity audit: primary=%s, qualified_capacity=%d, required=%d, fallback enabled=%v",
		primaryRegion, qualifiedCapacity, required, fallbackEnabled)

	res := &CandidateSelectionResult{
		QualifiedCapacity: int(qualifiedCapacity),
		PrimaryCount:      int(qualifiedCapacity),
		Required:          required,
		FallbackEnabled:   fallbackEnabled,
	}

	// Helper to query best unassigned candidate from a region
	queryBestCandidate := func(countryFilter string) (*models.Node, error) {
		var n models.Node
		q := database.DB.Where("status IN (?) AND fail_count < 3", candidateSelectStatuses)
		if countryFilter != "" {
			q = q.Where("UPPER(country) = ?", countryFilter)
		}
		// Prioritize QUALIFIED first, then HEALTHY, then DISCOVERED; order by score DESC
		err := q.Order("CASE WHEN status = 'QUALIFIED' THEN 1 WHEN status = 'HEALTHY' THEN 2 ELSE 3 END, score DESC").
			First(&n).Error
		if err != nil {
			return nil, err
		}
		return &n, nil
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

	var fbNode models.Node
	err := database.DB.Where("status IN (?) AND fail_count < 3 AND UPPER(country) IN ?",
		candidateSelectStatuses, fallbackUpper).
		Order("CASE WHEN status = 'QUALIFIED' THEN 1 WHEN status = 'HEALTHY' THEN 2 ELSE 3 END, score DESC").
		First(&fbNode).Error
	if err != nil {
		return nil, fmt.Errorf("no candidates found in fallback regions: %w", err)
	}

	res.Node = &fbNode
	res.IsFallbackNode = true
	log.Printf("[Scheduler] Primary candidates exhausted (%d < %d). Using Fallback node %s (%s, status=%s, score=%d)",
		qualifiedCapacity, required, fbNode.IP, fbNode.Country, fbNode.Status, fbNode.Score)
	return res, nil
}

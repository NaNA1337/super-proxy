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
	Node            *models.Node
	PrimaryCount    int
	Required        int
	FallbackEnabled bool
	IsFallbackNode  bool
}

// SelectNextCandidate audits eligible candidates in the database and returns the best node.
// GUARANTEES:
// 1. If primary candidates count >= required (MaxActive + MaxStandby), Fallback is strictly disabled.
// 2. High-score Fallback nodes can NEVER bypass Primary candidates when Primary >= required.
// 3. Even when Fallback is enabled (Primary < required), any available Primary nodes are exhausted first.
// 4. Detailed audit explanations are logged for full observability.
func (s *Scheduler) SelectNextCandidate() (*CandidateSelectionResult, error) {
	required := s.MaxActive + s.MaxStandby
	if required <= 0 {
		required = 5
	}

	primaryRegion := strings.ToUpper(strings.TrimSpace(s.RegionConfig.Primary))

	// 1. Count eligible candidates in Primary region
	var primaryCount int64
	primaryQuery := database.DB.Model(&models.Node{}).
		Where("status = ? AND fail_count < 3", models.StatusDiscovered)
	if primaryRegion != "" {
		primaryQuery = primaryQuery.Where("UPPER(country) = ?", primaryRegion)
	}
	if err := primaryQuery.Count(&primaryCount).Error; err != nil {
		return nil, fmt.Errorf("failed to count primary candidates in DB: %w", err)
	}

	fallbackEnabled := int(primaryCount) < required
	log.Printf("[Scheduler] Region candidate audit: primary=%s, candidates=%d, required=%d, fallback enabled=%v",
		primaryRegion, primaryCount, required, fallbackEnabled)

	res := &CandidateSelectionResult{
		PrimaryCount:    int(primaryCount),
		Required:        required,
		FallbackEnabled: fallbackEnabled,
	}

	var node models.Node

	// Case 1: Primary candidates meet or exceed required threshold -> Fallback is FORBIDDEN
	if !fallbackEnabled {
		err := database.DB.Where("status = ? AND fail_count < 3 AND UPPER(country) = ?",
			models.StatusDiscovered, primaryRegion).
			Order("score DESC").
			First(&node).Error
		if err != nil {
			return nil, fmt.Errorf("error selecting primary node: %w", err)
		}
		res.Node = &node
		res.IsFallbackNode = false
		log.Printf("[Scheduler] Candidate selected from Primary (%s, score=%d)", node.Country, node.Score)
		return res, nil
	}

	// Case 2: Fallback is enabled because Primary < required.
	// We STILL attempt to pick remaining Primary nodes first before falling back!
	err := database.DB.Where("status = ? AND fail_count < 3 AND UPPER(country) = ?",
		models.StatusDiscovered, primaryRegion).
		Order("score DESC").
		First(&node).Error
	if err == nil {
		res.Node = &node
		res.IsFallbackNode = false
		log.Printf("[Scheduler] Candidate selected from Primary (%s, score=%d) while fallback open", node.Country, node.Score)
		return res, nil
	}

	// Primary region is completely exhausted; select from Fallback regions
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

	err = database.DB.Where("status = ? AND fail_count < 3 AND UPPER(country) IN ?",
		models.StatusDiscovered, fallbackUpper).
		Order("score DESC").
		First(&node).Error
	if err != nil {
		return nil, fmt.Errorf("no candidates found in fallback regions: %w", err)
	}

	res.Node = &node
	res.IsFallbackNode = true
	log.Printf("[Scheduler] Primary candidates exhausted (%d < %d). Using Fallback node %s (%s, score=%d)",
		primaryCount, required, node.IP, node.Country, node.Score)
	return res, nil
}

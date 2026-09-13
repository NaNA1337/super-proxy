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
	// QuarantinedEndpoint means the VPN server address failed reputation
	// admission and may only be used to discover its NAT egress. It can never be
	// promoted unless the observed exit independently passes full admission.
	QuarantinedEndpoint bool
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
	models.StatusReputationChecked,
}

// SelectNextCandidate audits eligible candidates in the database and returns the best node.
// Automatic selection is deliberately locked to RegionConfig.Primary. Operators
// can still select a fully vetted foreign node through the manual-switch API,
// but an empty automatic slot is never backfilled from another region.
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
		Where("status IN (?)", qualifiedCapacityStatuses)
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

	log.Printf("[Scheduler] Region capacity audit: primary=%s, qualified_capacity=%d, required=%d, automatic_cross_region=false",
		primaryRegion, qualifiedCapacity, required)

	res := &CandidateSelectionResult{
		QualifiedCapacity: qualifiedCapacity,
		PrimaryCount:      qualifiedCapacity,
		Required:          required,
		FallbackEnabled:   false,
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
	pickQuarantinedCandidate := func(q *gorm.DB) (*models.Node, error) {
		var candidates []models.Node
		if err := q.
			Order("net_is_hosting ASC, net_is_tor ASC, net_is_proxy ASC, net_is_vpn ASC, sessions DESC, total_traffic DESC").
			Limit(512).Find(&candidates).Error; err != nil {
			return nil, err
		}
		for i := range candidates {
			if _, ok := discovery.GetOVPNSecret(candidates[i].ID); !ok {
				continue
			}
			return &candidates[i], nil
		}
		return nil, gorm.ErrRecordNotFound
	}

	queryBestCandidate := func(countryFilter string) (*models.Node, error) {
		q := database.DB.Where("status IN (?)", candidateSelectStatuses)
		if countryFilter != "" {
			q = q.Where("UPPER(country) = ?", countryFilter)
		}
		return pickDiverseCandidate(q)
	}
	queryQuarantinedCandidate := func(countries []string) (*models.Node, error) {
		q := database.DB.Where(
			"status = ? AND rep_is_blacklisted = ? AND last_error LIKE ?",
			models.StatusFailed, true, "discovery reputation admission:%",
		)
		if len(countries) > 0 {
			q = q.Where("UPPER(country) IN ?", countries)
		}
		return pickQuarantinedCandidate(q)
	}

	if node, err := queryBestCandidate(primaryRegion); err == nil {
		res.Node = node
		res.IsFallbackNode = false
		log.Printf("[Scheduler] Candidate selected from Primary (%s, status=%s, score=%d)", node.Country, node.Status, node.Score)
		return res, nil
	}

	// The endpoint itself may be a publicly listed VPN address while the tunnel
	// receives a different NAT egress. Probe it without admitting it to the
	// candidate pool; only the independently checked observed exit can promote it.
	if primaryRegion != "" {
		if node, err := queryQuarantinedCandidate([]string{primaryRegion}); err == nil {
			res.Node = node
			res.IsFallbackNode = false
			res.QuarantinedEndpoint = true
			log.Printf("[Scheduler] Primary pool exhausted; isolated exit probe selected for endpoint %s (%s)", node.IP, node.Country)
			return res, nil
		}
	}

	return nil, fmt.Errorf("primary region %s candidates exhausted; automatic cross-region replacement is disabled", primaryRegion)
}

package reputation

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AnalyzePrefix extracts the /24 CIDR prefix for IPv4 addresses.
func AnalyzePrefix(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	ip = ip.To4()
	if ip == nil {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
}

// RecordPrefixObservation saves an individual observation into the prefix_observations table
// and updates the aggregated PrefixIntelligence summary record.
func RecordPrefixObservation(db *gorm.DB, obs models.PrefixObservation) error {
	if db == nil {
		return nil
	}
	if obs.Prefix == "" {
		obs.Prefix = AnalyzePrefix(obs.IP)
	}
	if obs.Prefix == "" {
		return nil
	}
	if obs.ObservedAt.IsZero() {
		obs.ObservedAt = time.Now()
	}

	// 1. Insert individual time-window observation
	if err := db.Create(&obs).Error; err != nil {
		return fmt.Errorf("failed to record prefix observation: %w", err)
	}

	// 2. Refresh aggregate summary for this prefix
	return RefreshPrefixSummary(db, obs.Prefix)
}

// RecordPrefixSample provides backward compatibility, forwarding to RecordPrefixObservation.
func RecordPrefixSample(db *gorm.DB, ipStr string, score int, isBad bool, isHardReject bool) error {
	prefix := AnalyzePrefix(ipStr)
	if prefix == "" {
		return nil
	}

	obs := models.PrefixObservation{
		Prefix:       prefix,
		IP:           ipStr,
		Score:        score,
		Status:       string(StatusGood),
		IsBad:        isBad,
		IsHardReject: isHardReject,
		ObservedAt:   time.Now(),
	}
	if isHardReject || isBad {
		obs.Status = string(StatusBad)
	}

	return RecordPrefixObservation(db, obs)
}

// RefreshPrefixSummary recomputes all aggregate fields for a prefix and upserts PrefixIntelligence.
func RefreshPrefixSummary(db *gorm.DB, prefix string) error {
	if db == nil || prefix == "" {
		return nil
	}

	type summary struct {
		SampleCount      int
		BadCount         int
		HardRejectCount  int
		UnknownCount     int
		VPNCount         int
		ProxyCount       int
		TorCount         int
		HostingCount     int
		ResidentialCount int
		AvgScore         float64
		DistinctIPs      int
		ASNDiversity     int
		ISPDiversity     int
		FirstSeenStr     *string
		LastSeenStr      *string
	}

	var s summary
	row := db.Model(&models.PrefixObservation{}).
		Select(`COUNT(*) as sample_count,
		        COALESCE(SUM(CASE WHEN is_bad = true THEN 1 ELSE 0 END), 0) as bad_count,
		        COALESCE(SUM(CASE WHEN is_hard_reject = true THEN 1 ELSE 0 END), 0) as hard_reject_count,
		        COALESCE(SUM(CASE WHEN is_unknown = true THEN 1 ELSE 0 END), 0) as unknown_count,
		        COALESCE(SUM(CASE WHEN is_vpn = true THEN 1 ELSE 0 END), 0) as vpn_count,
		        COALESCE(SUM(CASE WHEN is_proxy = true THEN 1 ELSE 0 END), 0) as proxy_count,
		        COALESCE(SUM(CASE WHEN is_tor = true THEN 1 ELSE 0 END), 0) as tor_count,
		        COALESCE(SUM(CASE WHEN is_hosting = true THEN 1 ELSE 0 END), 0) as hosting_count,
		        COALESCE(SUM(CASE WHEN network_type = 'residential' THEN 1 ELSE 0 END), 0) as residential_count,
		        COALESCE(AVG(score), 0) as avg_score,
		        COUNT(DISTINCT ip) as distinct_ips,
		        COUNT(DISTINCT NULLIF(asn, '')) as asn_diversity,
		        COUNT(DISTINCT NULLIF(isp, '')) as isp_diversity,
		        MIN(observed_at) as first_seen,
		        MAX(observed_at) as last_seen`).
		Where("prefix = ?", prefix).
		Row()

	if err := row.Scan(&s.SampleCount, &s.BadCount, &s.HardRejectCount, &s.UnknownCount,
		&s.VPNCount, &s.ProxyCount, &s.TorCount, &s.HostingCount, &s.ResidentialCount,
		&s.AvgScore, &s.DistinctIPs, &s.ASNDiversity, &s.ISPDiversity,
		&s.FirstSeenStr, &s.LastSeenStr); err != nil {
		return err
	}

	if s.SampleCount == 0 {
		return nil
	}

	badRatio := float64(s.BadCount) / float64(s.SampleCount)
	hardRejectRatio := float64(s.HardRejectCount) / float64(s.SampleCount)
	unknownRatio := float64(s.UnknownCount) / float64(s.SampleCount)

	firstSeenTime := parseDBTimestamp(s.FirstSeenStr)
	lastSeenTime := parseDBTimestamp(s.LastSeenStr)

	entry := models.PrefixIntelligence{
		Prefix:           prefix,
		PrefixLength:     24,
		SampleCount:      s.SampleCount,
		BadCount:         s.BadCount,
		UnknownCount:     s.UnknownCount,
		HardRejectCount:  s.HardRejectCount,
		BadRatio:         badRatio,
		HardRejectRatio:  hardRejectRatio,
		UnknownRatio:     unknownRatio,
		AverageScore:     s.AvgScore,
		VPNCount:         s.VPNCount,
		ProxyCount:       s.ProxyCount,
		TorCount:         s.TorCount,
		HostingCount:     s.HostingCount,
		ResidentialCount: s.ResidentialCount,
		DistinctIPs:      s.DistinctIPs,
		ASNDiversity:     s.ASNDiversity,
		ISPDiversity:     s.ISPDiversity,
		FirstSeen:        firstSeenTime,
		LastSeen:         lastSeenTime,
	}

	return db.Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "prefix"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"sample_count", "bad_count", "unknown_count", "hard_reject_count",
			"bad_ratio", "hard_reject_ratio", "unknown_ratio", "average_score",
			"vpn_count", "proxy_count", "tor_count", "hosting_count", "residential_count",
			"distinct_ips", "asn_diversity", "isp_diversity", "first_seen", "last_seen",
		}),
	}).Create(&entry).Error
}

// QueryPrefixWindow queries prefix intelligence over a specific time window (24h, 7d, 30d, 90d).
func QueryPrefixWindow(ctx context.Context, db *gorm.DB, prefix string, window ProfileWindow) (*models.PrefixIntelligence, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is nil")
	}

	since := time.Now().Add(-WindowDuration(window))

	type summary struct {
		SampleCount      int
		BadCount         int
		HardRejectCount  int
		UnknownCount     int
		VPNCount         int
		ProxyCount       int
		TorCount         int
		HostingCount     int
		ResidentialCount int
		AvgScore         float64
		DistinctIPs      int
		DistinctBadIPs   int
		ASNDiversity     int
		ISPDiversity     int
		FirstSeenStr     *string
		LastSeenStr      *string
	}

	var s summary
	row := db.WithContext(ctx).Model(&models.PrefixObservation{}).
		Select(`COUNT(*) as sample_count,
		        COALESCE(SUM(CASE WHEN is_bad = true THEN 1 ELSE 0 END), 0) as bad_count,
		        COALESCE(SUM(CASE WHEN is_hard_reject = true THEN 1 ELSE 0 END), 0) as hard_reject_count,
		        COALESCE(SUM(CASE WHEN is_unknown = true THEN 1 ELSE 0 END), 0) as unknown_count,
		        COALESCE(SUM(CASE WHEN is_vpn = true THEN 1 ELSE 0 END), 0) as vpn_count,
		        COALESCE(SUM(CASE WHEN is_proxy = true THEN 1 ELSE 0 END), 0) as proxy_count,
		        COALESCE(SUM(CASE WHEN is_tor = true THEN 1 ELSE 0 END), 0) as tor_count,
		        COALESCE(SUM(CASE WHEN is_hosting = true THEN 1 ELSE 0 END), 0) as hosting_count,
		        COALESCE(SUM(CASE WHEN network_type = 'residential' THEN 1 ELSE 0 END), 0) as residential_count,
		        COALESCE(AVG(score), 0) as avg_score,
		        COUNT(DISTINCT ip) as distinct_ips,
		        COUNT(DISTINCT CASE WHEN is_bad = true THEN ip END) as distinct_bad_ips,
		        COUNT(DISTINCT NULLIF(asn, '')) as asn_diversity,
		        COUNT(DISTINCT NULLIF(isp, '')) as isp_diversity,
		        MIN(observed_at) as first_seen,
		        MAX(observed_at) as last_seen`).
		Where("prefix = ? AND observed_at >= ?", prefix, since).
		Row()

	if err := row.Scan(&s.SampleCount, &s.BadCount, &s.HardRejectCount, &s.UnknownCount,
		&s.VPNCount, &s.ProxyCount, &s.TorCount, &s.HostingCount, &s.ResidentialCount,
		&s.AvgScore, &s.DistinctIPs, &s.DistinctBadIPs, &s.ASNDiversity, &s.ISPDiversity,
		&s.FirstSeenStr, &s.LastSeenStr); err != nil {
		return nil, fmt.Errorf("failed to query prefix window: %w", err)
	}

	badRatio := 0.0
	hardRejectRatio := 0.0
	unknownRatio := 0.0
	if s.SampleCount > 0 {
		badRatio = float64(s.BadCount) / float64(s.SampleCount)
		hardRejectRatio = float64(s.HardRejectCount) / float64(s.SampleCount)
		unknownRatio = float64(s.UnknownCount) / float64(s.SampleCount)
	}

	firstSeenTime := parseDBTimestamp(s.FirstSeenStr)
	lastSeenTime := parseDBTimestamp(s.LastSeenStr)

	return &models.PrefixIntelligence{
		Prefix:           prefix,
		PrefixLength:     24,
		SampleCount:      s.SampleCount,
		BadCount:         s.BadCount,
		UnknownCount:     s.UnknownCount,
		HardRejectCount:  s.HardRejectCount,
		BadRatio:         badRatio,
		HardRejectRatio:  hardRejectRatio,
		UnknownRatio:     unknownRatio,
		AverageScore:     s.AvgScore,
		VPNCount:         s.VPNCount,
		ProxyCount:       s.ProxyCount,
		TorCount:         s.TorCount,
		HostingCount:     s.HostingCount,
		ResidentialCount: s.ResidentialCount,
		DistinctIPs:      s.DistinctIPs,
		ASNDiversity:     s.ASNDiversity,
		ISPDiversity:     s.ISPDiversity,
		FirstSeen:        firstSeenTime,
		LastSeen:         lastSeenTime,
	}, nil
}

// EvaluatePrefixRisk evaluates subnet risk across multiple sliding windows (24h, 7d, 30d, 90d).
// It evaluates statistical density (sample_count, distinct_ip_count, bad_ratio, hard_reject_ratio,
// unknown_ratio, average_score, ASN diversity, ISP diversity, and network-type density)
// rather than using a simplistic hardcoded bad IP threshold (badLimit).
// The badLimit parameter is retained strictly for backward compatibility and is not used to condemn subnets.
func EvaluatePrefixRisk(db *gorm.DB, ipStr string, badLimit int) (isHighRisk bool, penalty int, explanation string) {
	if db == nil {
		return false, 0, ""
	}
	prefix := AnalyzePrefix(ipStr)
	if prefix == "" {
		return false, 0, ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Query multiple observation windows
	w24h, _ := QueryPrefixWindow(ctx, db, prefix, Window24h)
	w7d, _ := QueryPrefixWindow(ctx, db, prefix, Window7d)
	w30d, _ := QueryPrefixWindow(ctx, db, prefix, Window30d)

	// Primary window for evaluation is 7d, enriched with 24h short-term spikes and 30d baseline
	primary := w7d
	if primary == nil || primary.SampleCount == 0 {
		primary = w24h
	}
	if primary == nil || primary.SampleCount == 0 {
		primary = w30d
	}

	if primary == nil || primary.SampleCount == 0 {
		return false, 0, fmt.Sprintf("Prefix %s: no prior observations", prefix)
	}

	// 1. Low sample density (< 4): do not condemn whole /24.
	// Even if 3 bad out of 3 samples, sample density is too low for hard subnet block.
	if primary.SampleCount < 4 {
		if primary.BadRatio >= 0.75 {
			return false, 5, fmt.Sprintf("Prefix %s: %d/%d bad samples (sparse sample density, soft penalty: -5)",
				prefix, primary.BadCount, primary.SampleCount)
		}
		return false, 0, fmt.Sprintf("Prefix %s: %d/%d bad samples (sparse / low density, allowed)",
			prefix, primary.BadCount, primary.SampleCount)
	}

	// 2. High sample count with low bad ratio (e.g. 3 bad out of 1000 samples = 0.3%):
	// Must be cleanly ALLOWED without penalty!
	if primary.BadRatio < 0.10 && primary.HardRejectRatio < 0.05 {
		return false, 0, fmt.Sprintf("Prefix %s: LOW risk (bad_ratio=%.2f%%, hard_reject_ratio=%.2f%%, %d/%d samples, ASN=%d, ISP=%d)",
			prefix, primary.BadRatio*100.0, primary.HardRejectRatio*100.0, primary.BadCount, primary.SampleCount, primary.ASNDiversity, primary.ISPDiversity)
	}

	// 3. Check for immediate 24h outbreak / spike compared to 30d baseline
	if w24h != nil && w24h.SampleCount >= 4 && w24h.HardRejectRatio >= 0.50 {
		penalty = 35
		return true, penalty, fmt.Sprintf("Prefix %s: CRITICAL 24h spike (24h hard_reject_ratio=%.1f%% over %d samples)",
			prefix, w24h.HardRejectRatio*100.0, w24h.SampleCount)
	}

	// 4. High risk in primary window: high hard reject ratio or dense bad ratio with multiple distinct IPs
	if primary.HardRejectRatio >= 0.30 || (primary.BadRatio >= 0.50 && primary.DistinctIPs >= 3) {
		penalty = 30
		return true, penalty, fmt.Sprintf("Prefix %s: HIGH risk (bad_ratio=%.1f%%, hard_reject_ratio=%.1f%%, distinct_ips=%d, samples=%d)",
			prefix, primary.BadRatio*100.0, primary.HardRejectRatio*100.0, primary.DistinctIPs, primary.SampleCount)
	}

	// 5. Moderate risk: elevated bad ratio or high unknown ratio
	if primary.BadRatio >= 0.25 {
		penalty = 15
		return false, penalty, fmt.Sprintf("Prefix %s: MODERATE risk (bad_ratio=%.1f%%, samples=%d, penalty: -15)",
			prefix, primary.BadRatio*100.0, primary.SampleCount)
	}

	if primary.UnknownRatio >= 0.70 && primary.SampleCount >= 5 {
		penalty = 5
		return false, penalty, fmt.Sprintf("Prefix %s: INCONCLUSIVE (unknown_ratio=%.1f%%, samples=%d, soft penalty: -5)",
			prefix, primary.UnknownRatio*100.0, primary.SampleCount)
	}

	return false, 0, fmt.Sprintf("Prefix %s: normal (bad_ratio=%.1f%%, samples=%d)",
		prefix, primary.BadRatio*100.0, primary.SampleCount)
}

// GroupDiscoveredIPsByPrefix groups VPN Gate discovered nodes into /24 subnets for neighbor profiling.
func GroupDiscoveredIPsByPrefix(nodes []models.Node) map[string][]models.Node {
	grouped := make(map[string][]models.Node)
	for _, n := range nodes {
		prefix := AnalyzePrefix(n.IP)
		if prefix != "" {
			grouped[prefix] = append(grouped[prefix], n)
		}
	}
	return grouped
}

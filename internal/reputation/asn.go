package reputation

import (
	"context"
	"fmt"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
	"gorm.io/gorm"
)

// ProfileWindow defines standard evaluation time horizons.
type ProfileWindow string

const (
	Window24h ProfileWindow = "24h"
	Window7d  ProfileWindow = "7d"
	Window30d ProfileWindow = "30d"
	Window90d ProfileWindow = "90d"
)

// ASNProfile holds historical risk aggregation for an autonomous system.
type ASNProfile struct {
	ASN             string        `json:"asn"`
	ISP             string        `json:"isp"`
	Window          ProfileWindow `json:"window"`
	SampleCount     int           `json:"sample_count"`
	BadCount        int           `json:"bad_count"`
	HardRejectCount int           `json:"hard_reject_count"`
	UnknownCount    int           `json:"unknown_count"`
	BadRatio        float64       `json:"bad_ratio"`
	HardRejectRatio float64       `json:"hard_reject_ratio"`
	AverageScore    float64       `json:"average_score"`
	LastSeen        time.Time     `json:"last_seen"`
	RiskLevel       string        `json:"risk_level"` // LOW, MEDIUM, HIGH, CRITICAL
	ScorePenalty    int           `json:"score_penalty"`
}

// WindowDuration converts ProfileWindow to time.Duration.
func WindowDuration(w ProfileWindow) time.Duration {
	switch w {
	case Window24h:
		return 24 * time.Hour
	case Window7d:
		return 7 * 24 * time.Hour
	case Window30d:
		return 30 * 24 * time.Hour
	case Window90d:
		return 90 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}

// parseDBTimestamp parses timestamps returned by database aggregate functions (e.g. SQLite MAX/MIN).
func parseDBTimestamp(val *string) time.Time {
	if val == nil || *val == "" {
		return time.Time{}
	}
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, *val); err == nil {
			return t
		}
	}
	return time.Time{}
}

// QueryASNProfile calculates statistical risk profile for an ASN over the requested window.
func QueryASNProfile(ctx context.Context, db *gorm.DB, asn string, window ProfileWindow) (*ASNProfile, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is nil")
	}
	if asn == "" {
		return nil, fmt.Errorf("asn cannot be empty")
	}

	since := time.Now().Add(-WindowDuration(window))

	type stats struct {
		SampleCount     int
		BadCount        int
		HardRejectCount int
		UnknownCount    int
		AvgScore        float64
		LastSeenStr     *string
		ISP             *string
	}

	var res stats
	row := db.WithContext(ctx).Model(&models.ASNObservation{}).
		Select(`COUNT(*) as sample_count,
		        COALESCE(SUM(CASE WHEN is_bad = true THEN 1 ELSE 0 END), 0) as bad_count,
		        COALESCE(SUM(CASE WHEN is_hard_reject = true THEN 1 ELSE 0 END), 0) as hard_reject_count,
		        COALESCE(SUM(CASE WHEN is_unknown = true THEN 1 ELSE 0 END), 0) as unknown_count,
		        COALESCE(AVG(score), 0) as avg_score,
		        MAX(observed_at) as last_seen,
		        MAX(isp) as isp`).
		Where("asn = ? AND observed_at >= ?", asn, since).
		Row()

	if err := row.Scan(&res.SampleCount, &res.BadCount, &res.HardRejectCount, &res.UnknownCount, &res.AvgScore, &res.LastSeenStr, &res.ISP); err != nil {
		return nil, fmt.Errorf("failed to query ASN profile: %w", err)
	}

	lastSeenTime := parseDBTimestamp(res.LastSeenStr)
	ispStr := ""
	if res.ISP != nil {
		ispStr = *res.ISP
	}

	profile := &ASNProfile{
		ASN:             asn,
		ISP:             ispStr,
		Window:          window,
		SampleCount:     res.SampleCount,
		BadCount:        res.BadCount,
		HardRejectCount: res.HardRejectCount,
		UnknownCount:    res.UnknownCount,
		AverageScore:    res.AvgScore,
		LastSeen:        lastSeenTime,
		RiskLevel:       "LOW",
		ScorePenalty:    0,
	}

	if res.SampleCount > 0 {
		profile.BadRatio = float64(res.BadCount) / float64(res.SampleCount)
		profile.HardRejectRatio = float64(res.HardRejectCount) / float64(res.SampleCount)
	}

	// Dynamic risk classification based on sample density and ratios (avoiding naive thresholding)
	if res.SampleCount >= 5 {
		if profile.HardRejectRatio >= 0.4 || profile.BadRatio >= 0.75 {
			profile.RiskLevel = "CRITICAL"
			profile.ScorePenalty = 40
		} else if profile.BadRatio >= 0.5 {
			profile.RiskLevel = "HIGH"
			profile.ScorePenalty = 25
		} else if profile.BadRatio >= 0.25 {
			profile.RiskLevel = "MEDIUM"
			profile.ScorePenalty = 10
		}
	} else if res.SampleCount > 0 && profile.BadRatio >= 0.8 {
		// Low sample count with very high bad ratio -> soft penalty
		profile.RiskLevel = "MEDIUM"
		profile.ScorePenalty = 10
	}

	return profile, nil
}

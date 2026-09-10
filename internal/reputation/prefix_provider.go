package reputation

import (
	"context"
	"fmt"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
	"gorm.io/gorm"
)

// PrefixIntel defines structured external or local intelligence for an IP prefix.
type PrefixIntel struct {
	Prefix           string    `json:"prefix"`
	ASN              string    `json:"asn"`
	ISP              string    `json:"isp"`
	Organization     string    `json:"organization"`
	AbuseDensity     float64   `json:"abuse_density"`
	MaliciousDensity float64   `json:"malicious_density"`
	HostingDensity   float64   `json:"hosting_density"`
	VPNDensity       float64   `json:"vpn_density"`
	ProxyDensity     float64   `json:"proxy_density"`
	TorDensity       float64   `json:"tor_density"`
	ObservedIPCount  int       `json:"observed_ip_count"`
	BadIPCount       int       `json:"bad_ip_count"`
	LastObserved     time.Time `json:"last_observed"`
}

// PrefixProvider defines the interface for prefix-level reputation providers.
type PrefixProvider interface {
	LookupPrefix(ctx context.Context, prefix string) (*PrefixIntel, error)
	Name() string
}

// LocalPrefixProvider implements PrefixProvider using internal database observations.
type LocalPrefixProvider struct {
	db *gorm.DB
}

func NewLocalPrefixProvider(db *gorm.DB) *LocalPrefixProvider {
	return &LocalPrefixProvider{db: db}
}

func (l *LocalPrefixProvider) Name() string {
	return "LocalPrefixIntelligence"
}

func (l *LocalPrefixProvider) LookupPrefix(ctx context.Context, prefix string) (*PrefixIntel, error) {
	if l.db == nil {
		return nil, fmt.Errorf("database connection is nil")
	}

	since := time.Now().Add(-7 * 24 * time.Hour) // 7-day default evaluation window

	type aggStats struct {
		ObservedCount  int
		BadCount       int
		HardRejectCount int
		VPNCount       int
		ProxyCount     int
		TorCount       int
		HostingCount   int
		ASN            string
		ISP            string
		LastObserved   time.Time
	}

	var stats aggStats
	row := l.db.WithContext(ctx).Model(&models.PrefixObservation{}).
		Select(`COUNT(*) as observed_count,
		        COALESCE(SUM(CASE WHEN is_bad = true THEN 1 ELSE 0 END), 0) as bad_count,
		        COALESCE(SUM(CASE WHEN is_hard_reject = true THEN 1 ELSE 0 END), 0) as hard_reject_count,
		        COALESCE(SUM(CASE WHEN is_vpn = true THEN 1 ELSE 0 END), 0) as vpn_count,
		        COALESCE(SUM(CASE WHEN is_proxy = true THEN 1 ELSE 0 END), 0) as proxy_count,
		        COALESCE(SUM(CASE WHEN is_tor = true THEN 1 ELSE 0 END), 0) as tor_count,
		        COALESCE(SUM(CASE WHEN is_hosting = true THEN 1 ELSE 0 END), 0) as hosting_count,
		        COALESCE(MAX(asn), '') as asn,
		        COALESCE(MAX(isp), '') as isp,
		        COALESCE(MAX(observed_at), '1970-01-01') as last_observed`).
		Where("prefix = ? AND observed_at >= ?", prefix, since).
		Row()

	if err := row.Scan(&stats.ObservedCount, &stats.BadCount, &stats.HardRejectCount,
		&stats.VPNCount, &stats.ProxyCount, &stats.TorCount, &stats.HostingCount,
		&stats.ASN, &stats.ISP, &stats.LastObserved); err != nil {
		return nil, fmt.Errorf("failed to aggregate local prefix observations: %w", err)
	}

	if stats.ObservedCount == 0 {
		return &PrefixIntel{
			Prefix:       prefix,
			LastObserved: time.Now(),
		}, nil
	}

	total := float64(stats.ObservedCount)
	return &PrefixIntel{
		Prefix:           prefix,
		ASN:              stats.ASN,
		ISP:              stats.ISP,
		AbuseDensity:     float64(stats.BadCount) / total,
		MaliciousDensity: float64(stats.HardRejectCount) / total,
		HostingDensity:   float64(stats.HostingCount) / total,
		VPNDensity:       float64(stats.VPNCount) / total,
		ProxyDensity:     float64(stats.ProxyCount) / total,
		TorDensity:       float64(stats.TorCount) / total,
		ObservedIPCount:  stats.ObservedCount,
		BadIPCount:       stats.BadCount,
		LastObserved:     stats.LastObserved,
	}, nil
}

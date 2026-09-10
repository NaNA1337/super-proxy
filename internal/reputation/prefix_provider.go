package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
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
	ProviderName     string    `json:"provider_name"`
	IsExternal       bool      `json:"is_external"`
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
		ObservedCount   int
		BadCount        int
		HardRejectCount int
		VPNCount        int
		ProxyCount      int
		TorCount        int
		HostingCount    int
		ASN             string
		ISP             string
		LastObserved    time.Time
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
			ProviderName: l.Name(),
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
		ProviderName:     l.Name(),
	}, nil
}

// ExternalRDAPPrefixProvider queries standard public RDAP registries for CIDR allocation,
// ASN, and organization data with caching, retry with backoff, and strict timeout controls.
type ExternalRDAPPrefixProvider struct {
	client       *http.Client
	baseURL      string
	mu           sync.RWMutex
	cache        map[string]*rdapCacheEntry
	backoffUntil time.Time
}

type rdapCacheEntry struct {
	intel     *PrefixIntel
	expiresAt time.Time
}

func NewExternalRDAPPrefixProvider(customBaseURL string) *ExternalRDAPPrefixProvider {
	url := "https://rdap.arin.net/registry/ip"
	if customBaseURL != "" {
		url = strings.TrimRight(customBaseURL, "/")
	}
	return &ExternalRDAPPrefixProvider{
		client:  &http.Client{Timeout: 3 * time.Second},
		baseURL: url,
		cache:   make(map[string]*rdapCacheEntry),
	}
}

func (e *ExternalRDAPPrefixProvider) Name() string {
	return "ExternalRDAPPrefixProvider"
}

func (e *ExternalRDAPPrefixProvider) LookupPrefix(ctx context.Context, prefix string) (*PrefixIntel, error) {
	// 1. Check in-memory cache
	e.mu.RLock()
	if entry, ok := e.cache[prefix]; ok && time.Now().Before(entry.expiresAt) {
		e.mu.RUnlock()
		return entry.intel, nil
	}
	if time.Now().Before(e.backoffUntil) {
		e.mu.RUnlock()
		// Rate limited: provider failure must NEVER condemn the node, return nil without error
		return nil, nil
	}
	e.mu.RUnlock()

	// Extract sample IP from prefix (e.g., "198.51.100.0/24" -> "198.51.100.1")
	parts := strings.Split(prefix, "/")
	if len(parts) == 0 {
		return nil, nil
	}
	baseIP := parts[0]
	parsed := net.ParseIP(baseIP)
	if parsed == nil {
		return nil, nil
	}
	v4 := parsed.To4()
	if v4 == nil {
		return nil, nil
	}
	sampleIP := fmt.Sprintf("%d.%d.%d.1", v4[0], v4[1], v4[2])

	reqURL := fmt.Sprintf("%s/%s", e.baseURL, sampleIP)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("Accept", "application/rdap+json")

	// Retry loop with backoff (up to 2 retries)
	var resp *http.Response
	for attempt := 0; attempt < 2; attempt++ {
		resp, err = e.client.Do(req)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}

	if err != nil {
		// Network/provider failure: return nil without error to prevent false BAD categorization
		return nil, nil
	}
	defer resp.Body.Close()

	// Handle 429 rate-limiting with Retry-After
	if resp.StatusCode == http.StatusTooManyRequests {
		e.mu.Lock()
		retryAfterSec := 60
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if s, errAtoi := strconv.Atoi(ra); errAtoi == nil && s > 0 {
				retryAfterSec = s
			}
		}
		e.backoffUntil = time.Now().Add(time.Duration(retryAfterSec) * time.Second)
		e.mu.Unlock()
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var rdapResp struct {
		Name         string `json:"name"`
		Handle       string `json:"handle"`
		Country      string `json:"country"`
		StartAddress string `json:"startAddress"`
		EndAddress   string `json:"endAddress"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rdapResp); err != nil {
		return nil, nil
	}

	intel := &PrefixIntel{
		Prefix:       prefix,
		Organization: rdapResp.Name,
		LastObserved: time.Now(),
		ProviderName: e.Name(),
		IsExternal:   true,
	}

	// Cache result for 4 hours
	e.mu.Lock()
	e.cache[prefix] = &rdapCacheEntry{
		intel:     intel,
		expiresAt: time.Now().Add(4 * time.Hour),
	}
	e.mu.Unlock()

	return intel, nil
}

// NullExternalPrefixProvider is used when external prefix intelligence is unavailable or disabled.
type NullExternalPrefixProvider struct{}

func (n *NullExternalPrefixProvider) Name() string {
	return "NullExternalPrefixProvider (external prefix intelligence unavailable)"
}

func (n *NullExternalPrefixProvider) LookupPrefix(ctx context.Context, prefix string) (*PrefixIntel, error) {
	return nil, nil
}

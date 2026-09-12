package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
)

type ReputationStatus string

const (
	StatusGood    ReputationStatus = "GOOD"
	StatusRisky   ReputationStatus = "RISKY"
	StatusBad     ReputationStatus = "BAD"
	StatusUnknown ReputationStatus = "UNKNOWN"
)

// ReputationResult encapsulates detailed structured evidence from an individual provider.
type ReputationResult struct {
	Provider        string           `json:"provider"`
	IP              string           `json:"ip"`
	Status          ReputationStatus `json:"status"` // GOOD, BAD, UNKNOWN
	Score           *float64         `json:"score,omitempty"`
	AbuseConfidence *float64         `json:"abuse_confidence,omitempty"`
	FraudScore      *float64         `json:"fraud_score,omitempty"`
	IsVPN           *bool            `json:"is_vpn,omitempty"`
	IsProxy         *bool            `json:"is_proxy,omitempty"`
	IsTor           *bool            `json:"is_tor,omitempty"`
	IsHosting       *bool            `json:"is_hosting,omitempty"`
	IsResidential   *bool            `json:"is_residential,omitempty"`
	ASN             string           `json:"asn,omitempty"`
	ISP             string           `json:"isp,omitempty"`
	Organization    string           `json:"organization,omitempty"`
	Country         string           `json:"country,omitempty"`
	CountryCode     string           `json:"country_code,omitempty"`
	Reports         *int             `json:"reports,omitempty"`
	RawCategory     string           `json:"raw_category,omitempty"`
	ObservedAt      time.Time        `json:"observed_at"`
	Error           string           `json:"error,omitempty"`

	// Derived qualification attributes
	HardReject     bool                `json:"hard_reject"`
	ScorePenalty   int                 `json:"score_penalty"`
	ProviderReason string              `json:"provider_reason"`
	NetworkInfo    models.NetworkClass `json:"network_info"`
}

// Result defines the aggregate outcome of all reputation evaluations for an IP.
type Result struct {
	IP             string
	Country        string
	CountryCode    string
	Status         ReputationStatus
	HardReject     bool
	ScorePenalty   int
	ProviderReason string
	NetworkInfo    models.NetworkClass
	Evidences      []ReputationResult
}

// Provider represents a reputation API provider (AbuseIPDB, GreyNoise, IPQS, IPInfo).
type Provider interface {
	CheckIP(ctx context.Context, ip string) (*ReputationResult, error)
	Name() string
	IsHealthy() bool
}

// BaseProvider tracks backoff, 429 Retry-After, and health for API rate-limits and timeouts.
type BaseProvider struct {
	providerName   string
	mu             sync.RWMutex
	consecFailures int
	backoffUntil   time.Time
}

func (b *BaseProvider) SetName(name string) {
	b.providerName = name
}

func (b *BaseProvider) Name() string {
	return b.providerName
}

func (b *BaseProvider) IsHealthy() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return time.Now().After(b.backoffUntil)
}

func (b *BaseProvider) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consecFailures = 0
	b.backoffUntil = time.Time{}
}

func (b *BaseProvider) RecordFailure(isRateLimit bool, retryAfter time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consecFailures++
	if isRateLimit {
		if retryAfter > 0 {
			b.backoffUntil = time.Now().Add(retryAfter)
		} else {
			// Exponential backoff: 1m, 2m, 4m, up to 1h
			multiplier := 1 << (b.consecFailures - 1)
			if multiplier > 60 {
				multiplier = 60
			}
			b.backoffUntil = time.Now().Add(time.Duration(multiplier) * time.Minute)
		}
	} else if b.consecFailures >= 3 {
		// Backoff for 1 minute on repeated errors
		b.backoffUntil = time.Now().Add(1 * time.Minute)
	}
}

func parseRetryAfter(header string) time.Duration {
	header = strings.TrimSpace(header)
	if header == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(header); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if t, err := http.ParseTime(header); err == nil {
		diff := time.Until(t)
		if diff > 0 {
			return diff
		}
	}
	return 0
}

func boolPtr(b bool) *bool        { return &b }
func floatPtr(f float64) *float64 { return &f }
func intPtr(i int) *int           { return &i }

// ==========================================
// 1. GreyNoise Provider
// ==========================================

type GreyNoiseProvider struct {
	BaseProvider
	apiKey string
	client *http.Client
}

func NewGreyNoiseProvider(apiKey string) *GreyNoiseProvider {
	p := &GreyNoiseProvider{
		apiKey: apiKey,
		client: &http.Client{Timeout: 8 * time.Second},
	}
	p.SetName("GreyNoise")
	return p
}

type greyNoiseResponse struct {
	IP             string `json:"ip"`
	Noise          bool   `json:"noise"`
	Riot           bool   `json:"riot"`
	Classification string `json:"classification"` // "malicious", "benign", "unknown"
	Name           string `json:"name"`
	Message        string `json:"message"`
}

func (g *GreyNoiseProvider) CheckIP(ctx context.Context, ip string) (*ReputationResult, error) {
	now := time.Now()
	if !g.IsHealthy() {
		return &ReputationResult{
			Provider:       "GreyNoise",
			IP:             ip,
			Status:         StatusUnknown,
			ObservedAt:     now,
			ProviderReason: "GreyNoise in backoff",
			Error:          "provider in backoff",
		}, nil
	}

	reqURL := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	if g.apiKey != "" {
		req.Header.Set("key", g.apiKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		g.RecordFailure(false, 0)
		return nil, fmt.Errorf("GreyNoise request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		g.RecordFailure(true, retryAfter)
		return &ReputationResult{
			Provider:       "GreyNoise",
			IP:             ip,
			Status:         StatusUnknown,
			ObservedAt:     now,
			ProviderReason: "GreyNoise 429 Too Many Requests",
			Error:          "HTTP 429",
		}, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		g.RecordSuccess()
		return &ReputationResult{
			Provider:       "GreyNoise",
			IP:             ip,
			Status:         StatusGood,
			ObservedAt:     now,
			ProviderReason: "GreyNoise: not observed in internet background scanning",
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		g.RecordFailure(resp.StatusCode >= 500, 0)
		return nil, fmt.Errorf("GreyNoise returned status %d", resp.StatusCode)
	}

	var apiResp greyNoiseResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		g.RecordFailure(false, 0)
		return nil, fmt.Errorf("failed to decode GreyNoise response: %w", err)
	}
	g.RecordSuccess()

	res := &ReputationResult{
		Provider:    "GreyNoise",
		IP:          ip,
		RawCategory: apiResp.Name,
		ObservedAt:  now,
	}

	if apiResp.Classification == "malicious" {
		res.Status = StatusBad
		res.HardReject = true
		res.ProviderReason = fmt.Sprintf("GreyNoise: malicious scanner (%s)", apiResp.Name)
	} else if apiResp.Classification == "benign" || apiResp.Riot {
		res.Status = StatusGood
		res.ProviderReason = fmt.Sprintf("GreyNoise: benign/known service (%s)", apiResp.Name)
	} else {
		res.Status = StatusUnknown
		res.ProviderReason = "GreyNoise: observed scanning, classification unknown"
	}
	return res, nil
}

// ==========================================
// 2. IPQualityScore (IPQS) Provider
// ==========================================

type IPQSProvider struct {
	BaseProvider
	apiKey  string
	client  *http.Client
	baseURL string
}

func NewIPQSProvider(apiKey string) *IPQSProvider {
	return newIPQSProvider(apiKey, "https://ipqualityscore.com/api/json/ip", &http.Client{Timeout: 8 * time.Second})
}

func newIPQSProvider(apiKey, baseURL string, client *http.Client) *IPQSProvider {
	p := &IPQSProvider{
		apiKey:  apiKey,
		client:  client,
		baseURL: strings.TrimRight(baseURL, "/"),
	}
	p.SetName("IPQS")
	return p
}

type ipqsResponse struct {
	Success        bool   `json:"success"`
	Message        string `json:"message"`
	FraudScore     int    `json:"fraud_score"`
	CountryCode    string `json:"country_code"`
	ISP            string `json:"ISP"`
	ASN            int    `json:"ASN"`
	Organization   string `json:"organization"`
	IsCrawler      bool   `json:"is_crawler"`
	Proxy          bool   `json:"proxy"`
	VPN            bool   `json:"vpn"`
	Tor            bool   `json:"tor"`
	ActiveVPN      bool   `json:"active_vpn"`
	ActiveTor      bool   `json:"active_tor"`
	BotStatus      bool   `json:"bot_status"`
	RecentAbuse    bool   `json:"recent_abuse"`
	FrequentAbuser bool   `json:"frequent_abuser"`
	HighRiskAttack bool   `json:"high_risk_attacks"`
	AbuseVelocity  string `json:"abuse_velocity"`
	ConnectionType string `json:"connection_type"`
}

func (q *IPQSProvider) CheckIP(ctx context.Context, ip string) (*ReputationResult, error) {
	now := time.Now()
	if !q.IsHealthy() {
		return &ReputationResult{
			Provider:       "IPQS",
			IP:             ip,
			Status:         StatusUnknown,
			ObservedAt:     now,
			ProviderReason: "IPQS in backoff",
			Error:          "provider in backoff",
		}, nil
	}

	reqURL := fmt.Sprintf("%s/%s/%s?strictness=1&allow_public_access_points=false", q.baseURL, q.apiKey, ip)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := q.client.Do(req)
	if err != nil {
		q.RecordFailure(false, 0)
		return nil, fmt.Errorf("IPQS request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		q.RecordFailure(true, retryAfter)
		return &ReputationResult{
			Provider:       "IPQS",
			IP:             ip,
			Status:         StatusUnknown,
			ObservedAt:     now,
			ProviderReason: "IPQS 429 Too Many Requests",
			Error:          "HTTP 429",
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		q.RecordFailure(resp.StatusCode >= 500, 0)
		return nil, fmt.Errorf("IPQS returned status %d", resp.StatusCode)
	}

	var apiResp ipqsResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		q.RecordFailure(false, 0)
		return nil, fmt.Errorf("failed to decode IPQS response: %w", err)
	}
	if !apiResp.Success {
		q.RecordFailure(false, 0)
		return nil, fmt.Errorf("IPQS rejected lookup: %s", apiResp.Message)
	}
	q.RecordSuccess()

	asnStr := ""
	if apiResp.ASN > 0 {
		asnStr = fmt.Sprintf("AS%d", apiResp.ASN)
	}

	isVPN := apiResp.VPN || apiResp.ActiveVPN
	isProxy := apiResp.Proxy
	isTor := apiResp.Tor || apiResp.ActiveTor

	res := &ReputationResult{
		Provider:     "IPQS",
		IP:           ip,
		FraudScore:   floatPtr(float64(apiResp.FraudScore)),
		Score:        floatPtr(float64(apiResp.FraudScore)),
		IsVPN:        boolPtr(isVPN),
		IsProxy:      boolPtr(isProxy),
		IsTor:        boolPtr(isTor),
		ASN:          asnStr,
		ISP:          apiResp.ISP,
		Organization: apiResp.Organization,
		CountryCode:  apiResp.CountryCode,
		ObservedAt:   now,
		NetworkInfo: models.NetworkClass{
			ASN:          asnStr,
			ISP:          apiResp.ISP,
			Organization: apiResp.Organization,
			NetworkType:  strings.ToLower(apiResp.ConnectionType),
			IsVPN:        isVPN,
			IsProxy:      isProxy,
			IsTor:        isTor,
		},
	}

	activeAbuse := apiResp.RecentAbuse || apiResp.FrequentAbuser || apiResp.HighRiskAttack ||
		strings.EqualFold(apiResp.AbuseVelocity, "high")
	prohibitedTrait := isVPN || isProxy || isTor
	if prohibitedTrait || activeAbuse {
		res.Status = StatusBad
		res.HardReject = true
		res.ProviderReason = fmt.Sprintf("IPQS prohibited classification (VPN=%v, Proxy=%v, Tor=%v, RecentAbuse=%v, FrequentAbuser=%v, HighRiskAttacks=%v, AbuseVelocity=%s)",
			isVPN, isProxy, isTor, apiResp.RecentAbuse, apiResp.FrequentAbuser, apiResp.HighRiskAttack, apiResp.AbuseVelocity)
	} else if apiResp.FraudScore >= 90 || apiResp.BotStatus {
		res.Status = StatusBad
		res.HardReject = true
		res.ProviderReason = fmt.Sprintf("IPQS FraudScore: %d, Bot: %v (Hard Reject)", apiResp.FraudScore, apiResp.BotStatus)
	} else if apiResp.FraudScore >= 75 {
		res.Status = StatusBad
		res.ScorePenalty = apiResp.FraudScore / 4
		res.ProviderReason = fmt.Sprintf("IPQS High FraudScore: %d, Penalty: -%d", apiResp.FraudScore, res.ScorePenalty)
	} else if apiResp.FraudScore >= 25 {
		res.Status = StatusRisky
		res.ScorePenalty = apiResp.FraudScore / 5
		res.ProviderReason = fmt.Sprintf("IPQS Risky network trait (FraudScore: %d, VPN=%v, Proxy=%v, Tor=%v)", apiResp.FraudScore, isVPN, isProxy, isTor)
	} else {
		res.Status = StatusGood
		res.ProviderReason = fmt.Sprintf("IPQS Clean (FraudScore: %d)", apiResp.FraudScore)
	}

	return res, nil
}

// ==========================================
// 3. IPInfo Provider
// ==========================================

type IPInfoProvider struct {
	BaseProvider
	apiKey string
	client *http.Client
}

func NewIPInfoProvider(apiKey string) *IPInfoProvider {
	p := &IPInfoProvider{
		apiKey: apiKey,
		client: &http.Client{Timeout: 8 * time.Second},
	}
	p.SetName("IPInfo")
	return p
}

type ipInfoResponse struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	Org      string `json:"org"`
	Country  string `json:"country"`
	Privacy  struct {
		VPN     bool   `json:"vpn"`
		Proxy   bool   `json:"proxy"`
		Tor     bool   `json:"tor"`
		Relay   bool   `json:"relay"`
		Hosting bool   `json:"hosting"`
		Service string `json:"service"`
	} `json:"privacy"`
	Company struct {
		Name   string `json:"name"`
		Domain string `json:"domain"`
		Type   string `json:"type"` // "hosting", "business", "isp"
	} `json:"company"`
}

func (i *IPInfoProvider) CheckIP(ctx context.Context, ip string) (*ReputationResult, error) {
	now := time.Now()
	if !i.IsHealthy() {
		return &ReputationResult{
			Provider:       "IPInfo",
			IP:             ip,
			Status:         StatusUnknown,
			ObservedAt:     now,
			ProviderReason: "IPInfo in backoff",
			Error:          "provider in backoff",
		}, nil
	}

	reqURL := fmt.Sprintf("https://ipinfo.io/%s/json", ip)
	if i.apiKey != "" {
		reqURL += fmt.Sprintf("?token=%s", i.apiKey)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := i.client.Do(req)
	if err != nil {
		i.RecordFailure(false, 0)
		return nil, fmt.Errorf("IPInfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		i.RecordFailure(true, retryAfter)
		return &ReputationResult{
			Provider:       "IPInfo",
			IP:             ip,
			Status:         StatusUnknown,
			ObservedAt:     now,
			ProviderReason: "IPInfo 429 Too Many Requests",
			Error:          "HTTP 429",
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		i.RecordFailure(resp.StatusCode >= 500, 0)
		return nil, fmt.Errorf("IPInfo returned status %d", resp.StatusCode)
	}

	var apiResp ipInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		i.RecordFailure(false, 0)
		return nil, fmt.Errorf("failed to decode IPInfo response: %w", err)
	}
	i.RecordSuccess()

	// Parse ASN from org field (e.g. "AS15169 Google LLC")
	asn := ""
	orgName := apiResp.Org
	if strings.HasPrefix(apiResp.Org, "AS") {
		parts := strings.SplitN(apiResp.Org, " ", 2)
		asn = parts[0]
		if len(parts) > 1 {
			orgName = parts[1]
		}
	}

	isHosting := apiResp.Privacy.Hosting || apiResp.Company.Type == "hosting"
	isVPN := apiResp.Privacy.VPN
	isProxy := apiResp.Privacy.Proxy
	isTor := apiResp.Privacy.Tor
	isResidential := apiResp.Company.Type == "isp" && !isHosting

	status := StatusGood
	if isHosting || isVPN || isProxy {
		status = StatusRisky
	}

	res := &ReputationResult{
		Provider:      "IPInfo",
		IP:            ip,
		Status:        status,
		IsVPN:         boolPtr(isVPN),
		IsProxy:       boolPtr(isProxy),
		IsTor:         boolPtr(isTor),
		IsHosting:     boolPtr(isHosting),
		IsResidential: boolPtr(isResidential),
		ASN:           asn,
		Organization:  orgName,
		CountryCode:   apiResp.Country,
		RawCategory:   apiResp.Company.Type,
		ObservedAt:    now,
		NetworkInfo: models.NetworkClass{
			ASN:          asn,
			Organization: orgName,
			NetworkType:  apiResp.Company.Type,
			IsVPN:        isVPN,
			IsProxy:      isProxy,
			IsTor:        isTor,
			IsHosting:    isHosting,
		},
		ProviderReason: fmt.Sprintf("IPInfo: Org=%s, Hosting=%v, VPN=%v, Proxy=%v (Status=%s)", orgName, isHosting, isVPN, isProxy, status),
	}

	return res, nil
}

// ==========================================
// 4. NullProvider (Fallback / Testing)
// ==========================================

type NullProvider struct{}

func (n *NullProvider) Name() string    { return "NullProvider" }
func (n *NullProvider) IsHealthy() bool { return true }
func (n *NullProvider) CheckIP(ctx context.Context, ip string) (*ReputationResult, error) {
	return &ReputationResult{
		Provider:       "NullProvider",
		IP:             ip,
		Status:         StatusUnknown,
		HardReject:     false,
		ScorePenalty:   0,
		ObservedAt:     time.Now(),
		ProviderReason: "NullProvider: reputation checking bypassed",
	}, nil
}

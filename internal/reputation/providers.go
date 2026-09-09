package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
)

type ReputationStatus string

const (
	StatusGood    ReputationStatus = "GOOD"
	StatusBad     ReputationStatus = "BAD"
	StatusUnknown ReputationStatus = "UNKNOWN"
)

// Result defines the outcome of a reputation check
type Result struct {
	IP             string
	Status         ReputationStatus
	HardReject     bool
	ScorePenalty   int
	ProviderReason string
	NetworkInfo    models.NetworkClass
}

// Provider represents a reputation API provider (AbuseIPDB, GreyNoise, IPQS, IPInfo)
type Provider interface {
	CheckIP(ctx context.Context, ip string) (*Result, error)
	Name() string
	IsHealthy() bool
}

// BaseProvider tracks backoff and health for API rate-limits and timeouts.
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

func (b *BaseProvider) RecordFailure(isRateLimit bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.consecFailures++
	if isRateLimit {
		// Backoff for 5 minutes on HTTP 429
		b.backoffUntil = time.Now().Add(5 * time.Minute)
	} else if b.consecFailures >= 3 {
		// Backoff for 1 minute on repeated errors
		b.backoffUntil = time.Now().Add(1 * time.Minute)
	}
}

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

func (g *GreyNoiseProvider) CheckIP(ctx context.Context, ip string) (*Result, error) {
	if !g.IsHealthy() {
		return &Result{IP: ip, Status: StatusUnknown, ProviderReason: "GreyNoise in backoff"}, nil
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
		g.RecordFailure(false)
		return nil, fmt.Errorf("GreyNoise request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		g.RecordFailure(true)
		return &Result{IP: ip, Status: StatusUnknown, ProviderReason: "GreyNoise 429 Too Many Requests"}, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		g.RecordSuccess()
		return &Result{IP: ip, Status: StatusGood, ProviderReason: "GreyNoise: not observed in internet background scanning"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		g.RecordFailure(resp.StatusCode >= 500)
		return nil, fmt.Errorf("GreyNoise returned status %d", resp.StatusCode)
	}

	var apiResp greyNoiseResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		g.RecordFailure(false)
		return nil, fmt.Errorf("failed to decode GreyNoise response: %w", err)
	}
	g.RecordSuccess()

	res := &Result{IP: ip}
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
	apiKey string
	client *http.Client
}

func NewIPQSProvider(apiKey string) *IPQSProvider {
	p := &IPQSProvider{
		apiKey: apiKey,
		client: &http.Client{Timeout: 8 * time.Second},
	}
	p.SetName("IPQS")
	return p
}

type ipqsResponse struct {
	Success      bool   `json:"success"`
	Message      string `json:"message"`
	FraudScore   int    `json:"fraud_score"`
	CountryCode  string `json:"country_code"`
	ISP          string `json:"ISP"`
	ASN          int    `json:"ASN"`
	Organization string `json:"organization"`
	IsCrawler    bool   `json:"is_crawler"`
	Proxy        bool   `json:"proxy"`
	VPN          bool   `json:"vpn"`
	Tor          bool   `json:"tor"`
	ActiveVPN    bool   `json:"active_vpn"`
	ActiveTor    bool   `json:"active_tor"`
	BotStatus    bool   `json:"bot_status"`
}

func (q *IPQSProvider) CheckIP(ctx context.Context, ip string) (*Result, error) {
	if !q.IsHealthy() {
		return &Result{IP: ip, Status: StatusUnknown, ProviderReason: "IPQS in backoff"}, nil
	}

	reqURL := fmt.Sprintf("https://ipqualityscore.com/api/json/ip/%s/%s?strictness=1&allow_public_access_points=true", q.apiKey, ip)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := q.client.Do(req)
	if err != nil {
		q.RecordFailure(false)
		return nil, fmt.Errorf("IPQS request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		q.RecordFailure(true)
		return &Result{IP: ip, Status: StatusUnknown, ProviderReason: "IPQS 429 Too Many Requests"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		q.RecordFailure(resp.StatusCode >= 500)
		return nil, fmt.Errorf("IPQS returned status %d", resp.StatusCode)
	}

	var apiResp ipqsResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		q.RecordFailure(false)
		return nil, fmt.Errorf("failed to decode IPQS response: %w", err)
	}
	q.RecordSuccess()

	res := &Result{
		IP: ip,
		NetworkInfo: models.NetworkClass{
			ASN:          fmt.Sprintf("AS%d", apiResp.ASN),
			ISP:          apiResp.ISP,
			Organization: apiResp.Organization,
			IsVPN:        apiResp.VPN || apiResp.ActiveVPN,
			IsProxy:      apiResp.Proxy,
			IsTor:        apiResp.Tor || apiResp.ActiveTor,
		},
	}

	if apiResp.FraudScore >= 90 || apiResp.BotStatus {
		res.Status = StatusBad
		res.HardReject = true
		res.ProviderReason = fmt.Sprintf("IPQS FraudScore: %d, Bot: %v (Hard Reject)", apiResp.FraudScore, apiResp.BotStatus)
	} else if apiResp.FraudScore >= 50 {
		res.Status = StatusBad
		res.ScorePenalty = apiResp.FraudScore / 4
		res.ProviderReason = fmt.Sprintf("IPQS Moderate FraudScore: %d, Penalty: -%d", apiResp.FraudScore, res.ScorePenalty)
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

func (i *IPInfoProvider) CheckIP(ctx context.Context, ip string) (*Result, error) {
	if !i.IsHealthy() {
		return &Result{IP: ip, Status: StatusUnknown, ProviderReason: "IPInfo in backoff"}, nil
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
		i.RecordFailure(false)
		return nil, fmt.Errorf("IPInfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		i.RecordFailure(true)
		return &Result{IP: ip, Status: StatusUnknown, ProviderReason: "IPInfo 429 Too Many Requests"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		i.RecordFailure(resp.StatusCode >= 500)
		return nil, fmt.Errorf("IPInfo returned status %d", resp.StatusCode)
	}

	var apiResp ipInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		i.RecordFailure(false)
		return nil, fmt.Errorf("failed to decode IPInfo response: %w", err)
	}
	i.RecordSuccess()

	res := &Result{
		IP:     ip,
		Status: StatusGood,
		NetworkInfo: models.NetworkClass{
			Organization: apiResp.Org,
			NetworkType:  apiResp.Company.Type,
			IsVPN:        apiResp.Privacy.VPN,
			IsProxy:      apiResp.Privacy.Proxy,
			IsTor:        apiResp.Privacy.Tor,
			IsHosting:    apiResp.Privacy.Hosting || apiResp.Company.Type == "hosting",
		},
		ProviderReason: fmt.Sprintf("IPInfo: Org=%s, Hosting=%v, VPN=%v", apiResp.Org, apiResp.Privacy.Hosting, apiResp.Privacy.VPN),
	}

	return res, nil
}

// ==========================================
// 4. NullProvider (Fallback / Testing)
// ==========================================

type NullProvider struct{}

func (n *NullProvider) Name() string    { return "NullProvider" }
func (n *NullProvider) IsHealthy() bool { return true }
func (n *NullProvider) CheckIP(ctx context.Context, ip string) (*Result, error) {
	return &Result{
		IP:             ip,
		Status:         StatusUnknown,
		HardReject:     false,
		ScorePenalty:   0,
		ProviderReason: "NullProvider: reputation checking bypassed",
	}, nil
}

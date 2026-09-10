package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
)

// AbuseIPDBProvider implements the Provider interface using AbuseIPDB's API.
type AbuseIPDBProvider struct {
	BaseProvider
	apiKey string
	client *http.Client
}

// NewAbuseIPDBProvider creates a new AbuseIPDB reputation provider.
func NewAbuseIPDBProvider(apiKey string) *AbuseIPDBProvider {
	p := &AbuseIPDBProvider{
		apiKey: apiKey,
		client: &http.Client{Timeout: 8 * time.Second},
	}
	p.SetName("AbuseIPDB")
	return p
}

type abuseIPDBResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		IsPublic             bool   `json:"isPublic"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryCode          string `json:"countryCode"`
		UsageType            string `json:"usageType"`
		ISP                  string `json:"isp"`
		Domain               string `json:"domain"`
		TotalReports         int    `json:"totalReports"`
		IsTor                bool   `json:"isTor"`
	} `json:"data"`
}

func (a *AbuseIPDBProvider) CheckIP(ctx context.Context, ip string) (*ReputationResult, error) {
	now := time.Now()
	if !a.IsHealthy() {
		return &ReputationResult{
			Provider:       "AbuseIPDB",
			IP:             ip,
			Status:         StatusUnknown,
			ObservedAt:     now,
			ProviderReason: "AbuseIPDB in rate-limit/failure backoff",
			Error:          "provider in backoff",
		}, nil
	}

	reqURL := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90&verbose", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Key", a.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		a.RecordFailure(false, 0)
		return nil, fmt.Errorf("AbuseIPDB request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		a.RecordFailure(true, retryAfter)
		return &ReputationResult{
			Provider:       "AbuseIPDB",
			IP:             ip,
			Status:         StatusUnknown,
			ObservedAt:     now,
			ProviderReason: "AbuseIPDB 429 Too Many Requests",
			Error:          "HTTP 429",
		}, nil
	}
	if resp.StatusCode != http.StatusOK {
		a.RecordFailure(resp.StatusCode >= 500, 0)
		return nil, fmt.Errorf("AbuseIPDB returned status %d", resp.StatusCode)
	}

	var apiResp abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		a.RecordFailure(false, 0)
		return nil, fmt.Errorf("failed to decode AbuseIPDB response: %w", err)
	}
	a.RecordSuccess()

	score := apiResp.Data.AbuseConfidenceScore
	scoreFloat := float64(score)
	reportsCount := apiResp.Data.TotalReports

	res := &ReputationResult{
		Provider:        "AbuseIPDB",
		IP:              ip,
		Score:           floatPtr(scoreFloat),
		AbuseConfidence: floatPtr(scoreFloat),
		Reports:         intPtr(reportsCount),
		CountryCode:     apiResp.Data.CountryCode,
		ISP:             apiResp.Data.ISP,
		IsTor:           boolPtr(apiResp.Data.IsTor),
		RawCategory:     apiResp.Data.UsageType,
		ObservedAt:      now,
		NetworkInfo: models.NetworkClass{
			ISP:         apiResp.Data.ISP,
			NetworkType: apiResp.Data.UsageType,
			IsTor:       apiResp.Data.IsTor,
		},
	}

	if score > 90 {
		res.Status = StatusBad
		res.HardReject = true
		res.ProviderReason = fmt.Sprintf("Abuse confidence score: %d%% (>90%% hard reject threshold), %d reports", score, reportsCount)
	} else if score > 25 {
		res.Status = StatusBad
		res.ScorePenalty = score / 5
		res.ProviderReason = fmt.Sprintf("Moderate abuse score: %d%%, penalty: -%d", score, res.ScorePenalty)
	} else {
		res.Status = StatusGood
		res.ProviderReason = fmt.Sprintf("Clean (confidence: %d%%)", score)
	}

	return res, nil
}

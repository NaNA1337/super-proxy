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

func (a *AbuseIPDBProvider) CheckIP(ctx context.Context, ip string) (*Result, error) {
	if !a.IsHealthy() {
		return &Result{IP: ip, Status: StatusUnknown, ProviderReason: "AbuseIPDB in rate-limit/failure backoff"}, nil
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
		a.RecordFailure(false)
		return nil, fmt.Errorf("AbuseIPDB request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		a.RecordFailure(true)
		return &Result{IP: ip, Status: StatusUnknown, ProviderReason: "AbuseIPDB 429 Too Many Requests"}, nil
	}
	if resp.StatusCode != http.StatusOK {
		a.RecordFailure(resp.StatusCode >= 500)
		return nil, fmt.Errorf("AbuseIPDB returned status %d", resp.StatusCode)
	}

	var apiResp abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		a.RecordFailure(false)
		return nil, fmt.Errorf("failed to decode AbuseIPDB response: %w", err)
	}
	a.RecordSuccess()

	res := &Result{
		IP: ip,
		NetworkInfo: models.NetworkClass{
			ISP:         apiResp.Data.ISP,
			NetworkType: apiResp.Data.UsageType,
			IsTor:       apiResp.Data.IsTor,
		},
	}

	score := apiResp.Data.AbuseConfidenceScore
	if score > 90 {
		res.Status = StatusBad
		res.HardReject = true
		res.ProviderReason = fmt.Sprintf("Abuse confidence score: %d%% (>90%% hard reject threshold), %d reports", score, apiResp.Data.TotalReports)
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

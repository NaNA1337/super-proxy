package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// AbuseIPDBProvider implements the Provider interface using AbuseIPDB's API.
type AbuseIPDBProvider struct {
	apiKey string
	client *http.Client
}

// NewAbuseIPDBProvider creates a new AbuseIPDB reputation provider.
func NewAbuseIPDBProvider(apiKey string) *AbuseIPDBProvider {
	return &AbuseIPDBProvider{
		apiKey: apiKey,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (a *AbuseIPDBProvider) Name() string { return "AbuseIPDB" }

type abuseIPDBResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		IsPublic             bool   `json:"isPublic"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryCode          string `json:"countryCode"`
		ISP                  string `json:"isp"`
		TotalReports         int    `json:"totalReports"`
	} `json:"data"`
}

func (a *AbuseIPDBProvider) CheckIP(ctx context.Context, ip string) (*Result, error) {
	reqURL := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", ip)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Key", a.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("AbuseIPDB request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AbuseIPDB returned status %d", resp.StatusCode)
	}

	var apiResp abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode AbuseIPDB response: %w", err)
	}

	result := &Result{
		IP: ip,
	}

	score := apiResp.Data.AbuseConfidenceScore

	// Hard reject if confidence score is very high
	if score > 90 {
		result.HardReject = true
		result.ProviderReason = fmt.Sprintf("Abuse confidence score: %d%% (>90%% threshold), %d reports", score, apiResp.Data.TotalReports)
		return result, nil
	}

	// Soft penalty for moderate scores
	if score > 25 {
		result.ScorePenalty = score / 5 // Penalty proportional to score
		result.ProviderReason = fmt.Sprintf("Moderate abuse score: %d%%, penalty: -%d", score, result.ScorePenalty)
	} else {
		result.ProviderReason = fmt.Sprintf("Clean (score: %d%%)", score)
	}

	return result, nil
}

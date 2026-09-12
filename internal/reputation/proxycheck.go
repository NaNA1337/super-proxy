package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
)

const proxyCheckAPIURL = "https://proxycheck.io/v3/"

// ProxyCheckProvider implements proxycheck.io's stable v3 API. It supplies the
// ASN/allocation class and active proxy, VPN, Tor, hosting, scraper and abuse
// detections used by the fail-closed admission policy.
type ProxyCheckProvider struct {
	BaseProvider
	apiKey  string
	days    float64
	client  *http.Client
	baseURL string
}

type proxyCheckIPResult struct {
	Risk    int `json:"risk"`
	Network struct {
		ASN          string `json:"asn"`
		Provider     string `json:"provider"`
		Organisation string `json:"organisation"`
		Type         string `json:"type"`
	} `json:"network"`
	Location struct {
		Country     string `json:"country"`
		ISOCode     string `json:"isocode"`
		CountryName string `json:"country_name"`
		CountryCode string `json:"country_code"`
	} `json:"location"`
	Detections struct {
		Anonymous   bool `json:"anonymous"`
		Proxy       bool `json:"proxy"`
		VPN         bool `json:"vpn"`
		Tor         bool `json:"tor"`
		Hosting     bool `json:"hosting"`
		Scraper     bool `json:"scraper"`
		Compromised bool `json:"compromised"`
		Risk        int  `json:"risk"`
		Confidence  *int `json:"confidence"`
	} `json:"detections"`
	AttackHistory map[string]int `json:"attack_history"`
	Operator      *struct {
		Name     string   `json:"name"`
		Services []string `json:"services"`
	} `json:"operator"`
}

func NewProxyCheckProvider(apiKey string, days float64) *ProxyCheckProvider {
	return newProxyCheckProvider(apiKey, days, proxyCheckAPIURL, &http.Client{Timeout: 8 * time.Second})
}

func newProxyCheckProvider(apiKey string, days float64, baseURL string, client *http.Client) *ProxyCheckProvider {
	if days < 0.01 || days > 60 {
		days = 1
	}
	p := &ProxyCheckProvider{
		apiKey:  strings.TrimSpace(apiKey),
		days:    days,
		baseURL: strings.TrimRight(baseURL, "/") + "/",
		client:  client,
	}
	p.SetName("ProxyCheck.io")
	return p
}

func (p *ProxyCheckProvider) CheckIP(ctx context.Context, ip string) (*ReputationResult, error) {
	now := time.Now()
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return nil, fmt.Errorf("proxycheck.io requires a valid IP address: %q", ip)
	}
	if !p.IsHealthy() {
		return &ReputationResult{Provider: p.Name(), IP: parsed.String(), Status: StatusUnknown,
			ObservedAt: now, ProviderReason: "proxycheck.io provider in backoff", Error: "provider in backoff"}, nil
	}

	u, err := url.Parse(p.baseURL + url.PathEscape(parsed.String()))
	if err != nil {
		return nil, fmt.Errorf("build proxycheck.io URL: %w", err)
	}
	q := u.Query()
	if p.apiKey != "" {
		q.Set("key", p.apiKey)
	}
	q.Set("days", fmt.Sprintf("%g", p.days))
	q.Set("tag", "0")
	q.Set("p", "0")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create proxycheck.io request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "super-proxy/reputation-check")
	resp, err := p.client.Do(req)
	if err != nil {
		p.RecordFailure(false, 0)
		return nil, fmt.Errorf("proxycheck.io request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		p.RecordFailure(true, parseRetryAfter(resp.Header.Get("Retry-After")))
		return nil, fmt.Errorf("proxycheck.io rate limit or daily quota exceeded (HTTP 429)")
	}
	if resp.StatusCode != http.StatusOK {
		p.RecordFailure(resp.StatusCode >= 500, 0)
		return nil, fmt.Errorf("proxycheck.io returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		p.RecordFailure(false, 0)
		return nil, fmt.Errorf("read proxycheck.io response: %w", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		p.RecordFailure(false, 0)
		return nil, fmt.Errorf("decode proxycheck.io response: %w", err)
	}
	var status string
	_ = json.Unmarshal(envelope["status"], &status)
	var message string
	_ = json.Unmarshal(envelope["message"], &message)
	if status != "ok" && status != "warning" {
		p.RecordFailure(status == "denied", 0)
		return nil, fmt.Errorf("proxycheck.io status %q: %s", status, message)
	}
	raw, ok := envelope[parsed.String()]
	if !ok {
		p.RecordFailure(false, 0)
		return nil, fmt.Errorf("proxycheck.io response omitted result for %s", parsed.String())
	}
	var apiResult proxyCheckIPResult
	if err := json.Unmarshal(raw, &apiResult); err != nil {
		p.RecordFailure(false, 0)
		return nil, fmt.Errorf("decode proxycheck.io IP result: %w", err)
	}
	p.RecordSuccess()
	return buildProxyCheckResult(parsed.String(), now, apiResult), nil
}

func buildProxyCheckResult(ip string, observedAt time.Time, r proxyCheckIPResult) *ReputationResult {
	riskScore := r.Risk
	if r.Detections.Risk > riskScore {
		riskScore = r.Detections.Risk
	}
	country := firstNonEmpty(r.Location.Country, r.Location.CountryName)
	countryCode := firstNonEmpty(r.Location.ISOCode, r.Location.CountryCode)
	networkType := strings.ToLower(strings.TrimSpace(r.Network.Type))
	hosting := r.Detections.Hosting || networkType == "hosting"
	traits := make([]string, 0, 8)
	if r.Detections.Anonymous {
		traits = append(traits, "anonymous")
	}
	if r.Detections.Proxy {
		traits = append(traits, "public proxy")
	}
	if r.Detections.VPN {
		traits = append(traits, "VPN")
	}
	if r.Detections.Tor {
		traits = append(traits, "Tor")
	}
	if hosting {
		traits = append(traits, "hosting/datacenter")
	}
	if r.Detections.Scraper {
		traits = append(traits, "scraper")
	}
	if r.Detections.Compromised {
		traits = append(traits, "compromised/attack source")
	}

	operatorRisk := false
	if r.Operator != nil {
		for _, service := range r.Operator.Services {
			s := strings.ToLower(service)
			if strings.Contains(s, "proxi") || strings.Contains(s, "proxy") || strings.Contains(s, "vpn") {
				operatorRisk = true
				traits = append(traits, "anonymizing operator service "+service)
			}
		}
	}
	sort.Strings(traits)
	hardReject := len(traits) > 0 || operatorRisk || riskScore >= 51
	status := StatusGood
	penalty := 0
	if hardReject {
		status = StatusBad
	} else if riskScore > 25 {
		status = StatusRisky
		penalty = riskScore
	}
	reason := fmt.Sprintf("proxycheck.io v3: risk=%d, type=%s, ASN=%s", riskScore, firstNonEmpty(networkType, "unknown"), r.Network.ASN)
	if len(traits) > 0 {
		reason += ", detected=" + strings.Join(traits, ", ")
	} else if riskScore >= 51 {
		reason += ", high reputation risk"
	}
	if r.Detections.Confidence != nil {
		reason += fmt.Sprintf(", confidence=%d", *r.Detections.Confidence)
	}

	risk := float64(riskScore)
	residential := networkType == "residential"
	return &ReputationResult{
		Provider: pNameProxyCheck, IP: ip, Status: status, FraudScore: &risk,
		IsVPN: boolPtr(r.Detections.VPN), IsProxy: boolPtr(r.Detections.Proxy), IsTor: boolPtr(r.Detections.Tor),
		IsHosting: boolPtr(hosting), IsResidential: boolPtr(residential), ASN: r.Network.ASN,
		ISP: r.Network.Provider, Organization: r.Network.Organisation, Country: country,
		CountryCode: countryCode, RawCategory: networkType, ObservedAt: observedAt,
		HardReject: hardReject, ScorePenalty: penalty, ProviderReason: reason,
		NetworkInfo: models.NetworkClass{ASN: r.Network.ASN, ISP: r.Network.Provider,
			Organization: r.Network.Organisation, NetworkType: networkType, IsHosting: hosting,
			IsVPN: r.Detections.VPN, IsProxy: r.Detections.Proxy, IsTor: r.Detections.Tor},
	}
}

const pNameProxyCheck = "ProxyCheck.io"

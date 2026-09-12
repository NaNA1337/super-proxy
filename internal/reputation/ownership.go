package reputation

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
)

const ownershipAPIURL = "https://api.ipapi.is/"

// OwnershipProvider supplies baseline ASN and organization data without an API key.
// Hosting classification is intentionally conservative and only hard-rejects explicit
// hosting/cloud ownership matches. Keyed providers can add more detailed evidence.
type OwnershipProvider struct {
	BaseProvider
	client  *http.Client
	baseURL string
}

type ownershipResponse struct {
	IP           string `json:"ip"`
	IsBogon      bool   `json:"is_bogon"`
	IsDatacenter bool   `json:"is_datacenter"`
	IsVPN        bool   `json:"is_vpn"`
	IsProxy      bool   `json:"is_proxy"`
	IsTor        bool   `json:"is_tor"`
	IsAbuser     bool   `json:"is_abuser"`
	Company      string `json:"company"`
	ASN          string `json:"asn"`
}

var hostingOwnershipMarkers = []string{
	"akamai", "alibaba cloud", "amazon data", "amazon technologies", "amazon.com",
	"azure", "choopa", "cloud hosting", "cloudflare", "colocation", "colocrossing",
	"contabo", "data center", "datacenter", "datacamp", "dedicated server",
	"digital ocean", "digitalocean", "fastly", "frantech", "gmo internet",
	"google cloud", "hetzner", "hostinger", "hosting", "leaseweb", "linode",
	"m247", "microsoft corporation", "netcup", "oracle cloud", "ovh",
	"rackspace", "sakura internet", "scaleway", "server hosting", "servers.com",
	"tencent cloud", "the constant company", "vps", "vultr", "xserver",
	"zenlayer",
}

func NewOwnershipProvider() *OwnershipProvider {
	return newOwnershipProvider(ownershipAPIURL, &http.Client{Timeout: 8 * time.Second})
}

func newOwnershipProvider(baseURL string, client *http.Client) *OwnershipProvider {
	p := &OwnershipProvider{client: client, baseURL: baseURL}
	p.SetName("IPOwnership")
	return p
}

func (p *OwnershipProvider) CheckIP(ctx context.Context, ip string) (*ReputationResult, error) {
	now := time.Now()
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil || parsed.To4() == nil {
		return nil, fmt.Errorf("ownership lookup requires a valid IPv4 address: %q", ip)
	}
	if !p.IsHealthy() {
		return &ReputationResult{
			Provider:       p.Name(),
			IP:             ip,
			Status:         StatusUnknown,
			ObservedAt:     now,
			ProviderReason: "IP ownership provider in backoff",
			Error:          "provider in backoff",
		}, nil
	}

	reqURL := p.baseURL + "?q=" + url.QueryEscape(parsed.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create ownership request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "super-proxy/ownership-check")

	resp, err := p.client.Do(req)
	if err != nil {
		p.RecordFailure(false, 0)
		return nil, fmt.Errorf("ownership request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		p.RecordFailure(true, parseRetryAfter(resp.Header.Get("Retry-After")))
		return nil, fmt.Errorf("ownership provider rate limited the request")
	}
	if resp.StatusCode != http.StatusOK {
		p.RecordFailure(resp.StatusCode >= 500, 0)
		return nil, fmt.Errorf("ownership provider returned HTTP %d", resp.StatusCode)
	}

	var apiResp ownershipResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 64*1024))
	if err := decoder.Decode(&apiResp); err != nil {
		p.RecordFailure(false, 0)
		return nil, fmt.Errorf("decode ownership response: %w", err)
	}
	p.RecordSuccess()

	asn, asnOrg := splitASN(apiResp.ASN)
	company := strings.TrimSpace(apiResp.Company)
	if apiResp.IsBogon {
		return &ReputationResult{
			Provider:       p.Name(),
			IP:             parsed.String(),
			Status:         StatusBad,
			HardReject:     true,
			ASN:            asn,
			ISP:            company,
			Organization:   asnOrg,
			ObservedAt:     now,
			ProviderReason: "ownership lookup identified a bogon address",
		}, nil
	}
	hosting, marker := ownershipLooksHosting(company, asnOrg)
	hosting = hosting || apiResp.IsDatacenter
	networkType := "isp"
	status := StatusGood
	reason := fmt.Sprintf("ASN ownership: %s, organization=%s", asn, firstNonEmpty(company, asnOrg))
	if hosting {
		networkType = "hosting"
		status = StatusBad
		if apiResp.IsDatacenter {
			reason = "ownership provider classified address as datacenter/hosting"
		} else {
			reason = fmt.Sprintf("hosting ownership marker %q matched ASN/company data", marker)
		}
	}
	traits := make([]string, 0, 4)
	if apiResp.IsVPN {
		traits = append(traits, "VPN")
	}
	if apiResp.IsProxy {
		traits = append(traits, "public proxy")
	}
	if apiResp.IsTor {
		traits = append(traits, "Tor")
	}
	if apiResp.IsAbuser {
		traits = append(traits, "recent abuse")
	}
	if len(traits) > 0 {
		status = StatusBad
		reason = "ownership provider prohibited classification: " + strings.Join(traits, ", ")
	}
	if asn == "" || (company == "" && asnOrg == "") {
		if !hosting && len(traits) == 0 {
			return &ReputationResult{
				Provider:       p.Name(),
				IP:             parsed.String(),
				Status:         StatusUnknown,
				ObservedAt:     now,
				ProviderReason: "ownership lookup returned no usable ASN or organization",
			}, nil
		}
	}

	return &ReputationResult{
		Provider:       p.Name(),
		IP:             parsed.String(),
		Status:         status,
		HardReject:     hosting || len(traits) > 0,
		IsHosting:      boolPtr(hosting),
		IsVPN:          boolPtr(apiResp.IsVPN),
		IsProxy:        boolPtr(apiResp.IsProxy),
		IsTor:          boolPtr(apiResp.IsTor),
		ASN:            asn,
		ISP:            company,
		Organization:   asnOrg,
		RawCategory:    networkType,
		ObservedAt:     now,
		ProviderReason: reason,
		NetworkInfo: models.NetworkClass{
			ASN:          asn,
			ISP:          company,
			Organization: asnOrg,
			NetworkType:  networkType,
			IsHosting:    hosting,
			IsVPN:        apiResp.IsVPN,
			IsProxy:      apiResp.IsProxy,
			IsTor:        apiResp.IsTor,
		},
	}, nil
}

func splitASN(value string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(value), " ", 2)
	if len(parts) == 0 || !strings.HasPrefix(strings.ToUpper(parts[0]), "AS") {
		return "", strings.TrimSpace(value)
	}
	organization := ""
	if len(parts) == 2 {
		organization = strings.TrimSpace(parts[1])
	}
	return strings.ToUpper(parts[0]), organization
}

func ownershipLooksHosting(values ...string) (bool, string) {
	combined := strings.ToLower(strings.Join(values, " "))
	for _, marker := range hostingOwnershipMarkers {
		if strings.Contains(combined, marker) {
			return true, marker
		}
	}
	return false, ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return "unknown"
}

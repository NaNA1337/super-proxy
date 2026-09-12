package reputation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProxyCheckProviderCleanResidential(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("days") != "1" || r.URL.Query().Get("tag") != "0" {
			t.Fatalf("missing expected conservative query flags: %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","198.51.100.7":{"network":{"asn":"AS64500","provider":"Example Fiber","organisation":"Example ISP","type":"Residential"},"location":{"country_name":"Japan","country_code":"JP"},"detections":{"anonymous":false,"proxy":false,"vpn":false,"tor":false,"hosting":false,"scraper":false,"compromised":false,"risk":8,"confidence":null},"attack_history":null,"operator":null},"queries_left":999}`))
	}))
	defer server.Close()

	p := newProxyCheckProvider("test-key", 1, server.URL, server.Client())
	result, err := p.CheckIP(context.Background(), "198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusGood || result.HardReject || result.ASN != "AS64500" {
		t.Fatalf("unexpected clean result: %+v", result)
	}
	if result.NetworkInfo.NetworkType != "residential" || result.NetworkInfo.ISP != "Example Fiber" {
		t.Fatalf("network classification was not mapped: %+v", result.NetworkInfo)
	}
	if result.CountryCode != "JP" {
		t.Fatalf("live v3 country_code shape was not mapped: %+v", result)
	}
}

func TestProxyCheckProviderRejectsHostingVPN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","203.0.113.9":{"risk":50,"network":{"asn":"AS64501","provider":"Example Cloud","organisation":"Example Cloud","type":"Hosting"},"location":{"country":"Japan","isocode":"JP"},"detections":{"anonymous":true,"proxy":false,"vpn":true,"tor":false,"hosting":true,"scraper":false,"compromised":false,"confidence":99},"attack_history":{},"operator":{"name":"Example VPN","services":["datacenter_vpns"]}}}`))
	}))
	defer server.Close()

	p := newProxyCheckProvider("test-key", 1, server.URL, server.Client())
	result, err := p.CheckIP(context.Background(), "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if !result.HardReject || !result.NetworkInfo.IsHosting || !result.NetworkInfo.IsVPN {
		t.Fatalf("hosting VPN must be rejected: %+v", result)
	}
	if !strings.Contains(result.ProviderReason, "hosting/datacenter") {
		t.Fatalf("missing rejection evidence: %s", result.ProviderReason)
	}
}

func TestProxyCheckProviderRejectsHighRiskWithoutTypeFlag(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","192.0.2.8":{"risk":76,"network":{"asn":"AS64502","provider":"Example","organisation":"Example","type":"Business"},"location":{},"detections":{"anonymous":false,"proxy":false,"vpn":false,"tor":false,"hosting":false,"scraper":false,"compromised":false,"confidence":null},"attack_history":{"login_attempt":4},"operator":null}}`))
	}))
	defer server.Close()

	p := newProxyCheckProvider("test-key", 1, server.URL, server.Client())
	result, err := p.CheckIP(context.Background(), "192.0.2.8")
	if err != nil {
		t.Fatal(err)
	}
	if !result.HardReject || result.Status != StatusBad {
		t.Fatalf("high-risk IP must be rejected: %+v", result)
	}
}

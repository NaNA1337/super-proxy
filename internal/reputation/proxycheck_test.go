package reputation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func TestProxyCheckQuotaBackoffStopsQueuedRequests(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"status":"denied","message":"Free queries exhausted."}`))
	}))
	defer server.Close()

	p := newProxyCheckProvider("test-key", 1, server.URL, server.Client())
	p.queries = make(chan struct{}, 1)
	var wg sync.WaitGroup
	for range 25 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.CheckIP(context.Background(), "198.51.100.7")
		}()
	}
	wg.Wait()
	if got := requests.Load(); got != 2 {
		t.Fatalf("expected one keyed request and one anonymous fallback before backoff; got %d requests", got)
	}
}

func TestProxyCheckUsesAnonymousAllowanceAfterKeyQuota(t *testing.T) {
	var keyedRequests atomic.Int32
	var anonymousRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "" {
			keyedRequests.Add(1)
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"status":"denied","message":"1,000 Free queries exhausted."}`))
			return
		}
		anonymousRequests.Add(1)
		_, _ = w.Write([]byte(`{"status":"ok","198.51.100.7":{"risk":4,"network":{"asn":"AS64500","provider":"Example Fiber","organisation":"Example ISP","type":"Residential"},"location":{"country_name":"Japan","country_code":"JP"},"detections":{}}}`))
	}))
	defer server.Close()

	p := newProxyCheckProvider("test-key", 1, server.URL, server.Client())
	result, err := p.CheckIP(context.Background(), "198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusGood || result.CountryCode != "JP" {
		t.Fatalf("unexpected anonymous fallback result: %+v", result)
	}
	if keyedRequests.Load() != 1 || anonymousRequests.Load() != 1 {
		t.Fatalf("unexpected request split: keyed=%d anonymous=%d", keyedRequests.Load(), anonymousRequests.Load())
	}
	if p.activeAPIKey(time.Now()) != "" {
		t.Fatal("exhausted key must remain disabled for the daily backoff window")
	}
}

func TestProxyCheckProviderReportsDailyQuotaAndBacksOff(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"status":"denied","message":"1,000 Free queries exhausted. Please try the API again tomorrow."}`))
	}))
	defer server.Close()

	p := newProxyCheckProvider("test-key", 1, server.URL, server.Client())
	_, err := p.CheckIP(context.Background(), "198.51.100.7")
	if err == nil || !strings.Contains(err.Error(), "queries exhausted") {
		t.Fatalf("expected actionable quota error, got %v", err)
	}
	if p.IsHealthy() {
		t.Fatal("daily quota exhaustion must put the provider into backoff")
	}
	if got := proxyCheckDailyQuotaBackoff(time.Date(2026, 9, 13, 23, 50, 0, 0, time.UTC)); got != time.Hour {
		t.Fatalf("near-midnight quota backoff must retain the one-hour minimum, got %s", got)
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

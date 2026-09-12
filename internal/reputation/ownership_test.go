package reputation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOwnershipProviderPopulatesASNWithoutAPIKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("q"); got != "126.37.15.22" {
			t.Fatalf("unexpected lookup IP: %s", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"126.37.15.22","is_bogon":false,"company":"SOFTBANK Corp.","asn":"AS17676 SoftBank Mobile Corp."}`))
	}))
	defer server.Close()

	provider := newOwnershipProvider(server.URL, server.Client())
	result, err := provider.CheckIP(context.Background(), "126.37.15.22")
	if err != nil {
		t.Fatalf("CheckIP failed: %v", err)
	}
	if result.ASN != "AS17676" || result.NetworkInfo.ASN != "AS17676" {
		t.Fatalf("expected AS17676, got result=%q network=%q", result.ASN, result.NetworkInfo.ASN)
	}
	if result.NetworkInfo.ISP != "SOFTBANK Corp." || result.NetworkInfo.IsHosting {
		t.Fatalf("unexpected SoftBank classification: %+v", result.NetworkInfo)
	}
	if result.Status != StatusGood || result.HardReject {
		t.Fatalf("residential ISP ownership must be allowed: %+v", result)
	}
}

func TestOwnershipProviderHardRejectsHostingASN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"198.13.38.5","is_bogon":false,"company":"Vultr Holdings, LLC","asn":"AS20473 The Constant Company, LLC"}`))
	}))
	defer server.Close()

	provider := newOwnershipProvider(server.URL, server.Client())
	result, err := provider.CheckIP(context.Background(), "198.13.38.5")
	if err != nil {
		t.Fatalf("CheckIP failed: %v", err)
	}
	if result.ASN != "AS20473" || !result.NetworkInfo.IsHosting {
		t.Fatalf("expected Vultr hosting classification: %+v", result)
	}
	if result.Status != StatusBad || !result.HardReject {
		t.Fatalf("hosting ASN must be hard rejected: %+v", result)
	}
}

func TestOwnershipProviderHardRejectsProviderThreatFlags(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ip":"198.51.100.8","is_proxy":true,"is_abuser":true}`))
	}))
	defer server.Close()

	provider := newOwnershipProvider(server.URL, server.Client())
	result, err := provider.CheckIP(context.Background(), "198.51.100.8")
	if err != nil {
		t.Fatal(err)
	}
	if !result.HardReject || result.Status != StatusBad || !result.NetworkInfo.IsProxy {
		t.Fatalf("provider threat flags must hard reject: %+v", result)
	}
}

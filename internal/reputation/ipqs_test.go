package reputation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIPQSHardRejectsProxyVPNAndRecentActivity(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "public proxy", body: `{"success":true,"proxy":true,"fraud_score":1}`},
		{name: "active vpn", body: `{"success":true,"active_vpn":true,"fraud_score":1}`},
		{name: "recent abuse", body: `{"success":true,"recent_abuse":true,"fraud_score":1}`},
		{name: "frequent abuser", body: `{"success":true,"frequent_abuser":true,"fraud_score":1}`},
		{name: "high abuse velocity", body: `{"success":true,"abuse_velocity":"high","fraud_score":1}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("allow_public_access_points") != "false" {
					t.Fatalf("public access points must not be allowed: %s", r.URL.RawQuery)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()

			provider := newIPQSProvider("test-key", server.URL, server.Client())
			result, err := provider.CheckIP(context.Background(), "198.51.100.9")
			if err != nil {
				t.Fatal(err)
			}
			if !result.HardReject || result.Status != StatusBad || !strings.Contains(result.ProviderReason, "prohibited classification") {
				t.Fatalf("%s must hard reject: %+v", tc.name, result)
			}
		})
	}
}

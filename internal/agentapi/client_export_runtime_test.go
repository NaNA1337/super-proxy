package agentapi

import (
	"net/http/httptest"
	"testing"

	"github.com/NaNA1337/super-proxy/internal/xray"
)

func TestRealityProfileIgnoresLegacyCredentialEnvironmentOverrides(t *testing.T) {
	xray.ClearRuntimeVlessEndpoint()
	defer xray.ClearRuntimeVlessEndpoint()
	defer SetActiveVlessConfig(nil)

	privateKey, publicKey, err := xray.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := xray.VlessConfig{
		Enabled:       true,
		Listen:        "0.0.0.0",
		Port:          443,
		PublicAddress: "198.51.100.20",
		UUID:          "0241c83f-1b06-4ed5-a83b-48971d39f43f",
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		ShortIds:      []string{"e9d66795d31539cd"},
		Flow:          xray.DefaultFlow,
		Dest:          xray.DefaultRealityTarget,
		ServerNames:   []string{xray.DefaultRealitySNI},
		Fingerprint:   xray.DefaultRealityFP,
	}
	SetActiveVlessConfig(&cfg)
	if err := xray.SetRuntimeVlessEndpoint(xray.PublicEndpoint{
		Address: "198.51.100.20", Port: 443, Network: "tcp", TLS: true, Protocol: "vless",
	}); err != nil {
		t.Fatal(err)
	}

	t.Setenv("XRAY_VLESS_UUID", "11111111-1111-4111-8111-111111111111")
	t.Setenv("XRAY_VLESS_PUBLIC_KEY", "stale-public-key")
	t.Setenv("XRAY_VLESS_SHORT_ID", "0000000000000000")
	t.Setenv("XRAY_VLESS_SNI", "example.com")

	profile, err := BuildRealityClientProfile(httptest.NewRequest("GET", "https://manager.example/api/v1/client-config/all", nil))
	if err != nil {
		t.Fatal(err)
	}
	if profile.UUID != cfg.UUID || profile.PublicKey != cfg.PublicKey || profile.ShortID != cfg.ShortIds[0] || profile.SNI != cfg.ServerNames[0] {
		t.Fatalf("exported profile diverged from loaded Xray credentials: %+v", profile)
	}
}

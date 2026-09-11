package xray

import "testing"

func TestNormalizeRealityKeypair(t *testing.T) {
	private, public, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	cfg := VlessConfig{Enabled: true, PrivateKey: private}
	if err := NormalizeVlessConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.PublicKey != public {
		t.Fatal("derived public key does not match private key")
	}
	cfg.PublicKey = "mismatched"
	if NormalizeVlessConfig(&cfg) == nil {
		t.Fatal("mismatched key pair accepted")
	}
}

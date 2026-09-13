package config

import (
	"os"
	"path/filepath"
	"testing"
)

func validTestConfig(listen string) *Config {
	return &Config{
		API:        APIConfig{Listen: listen, Port: 60000},
		Database:   DatabaseConfig{Path: "/tmp/super-proxy-test.db"},
		Discovery:  DiscoveryConfig{URL: "https://www.vpngate.net/api/iphone/", Interval: 15},
		Reputation: ReputationConfig{FailurePolicy: "conservative", ProxyCheckDays: 1},
	}
}

func TestValidateAcceptsRemoteAPIWildcard(t *testing.T) {
	cfg := validTestConfig(" 0.0.0.0 \n")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("remote Manager wildcard must be accepted: %v", err)
	}
	if cfg.API.Listen != "0.0.0.0" {
		t.Fatalf("listen address was not normalized: %q", cfg.API.Listen)
	}
}

func TestLoadConfigAcceptsQuotedRemoteAPIWildcard(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("api:\n  listen: \"0.0.0.0\"\n  port: 60000\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("quoted wildcard YAML must load: %v", err)
	}
	if cfg.API.Listen != "0.0.0.0" {
		t.Fatalf("unexpected loaded listen address: %q", cfg.API.Listen)
	}
}

func TestValidateAcceptsIPv6APIWildcard(t *testing.T) {
	for _, listen := range []string{"::", "[::]"} {
		if err := validTestConfig(listen).Validate(); err != nil {
			t.Fatalf("IPv6 wildcard %q must be accepted: %v", listen, err)
		}
	}
}

func TestValidateRejectsInvalidAPIListen(t *testing.T) {
	if err := validTestConfig("0.0.0.0.example").Validate(); err == nil {
		t.Fatal("invalid listen hostname was accepted")
	}
}

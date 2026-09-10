package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/NaNA1337/super-proxy/internal/xray"
	"github.com/spf13/viper"
)

type Config struct {
	Region     RegionConfig     `mapstructure:"region"`
	Database   DatabaseConfig   `mapstructure:"database"`
	Discovery  DiscoveryConfig  `mapstructure:"discovery"`
	Reputation ReputationConfig `mapstructure:"reputation"`
	Scoring    ScoringConfig    `mapstructure:"scoring"`
	SpeedTest  SpeedTestConfig  `mapstructure:"speed_test"`
	APIKey     string           `mapstructure:"api_key"`
	API        APIConfig        `mapstructure:"api"`
	Xray       XrayAppConfig    `mapstructure:"xray"`
}

type XrayAppConfig struct {
	Vless xray.VlessConfig `mapstructure:"vless"`
}

type APIConfig struct {
	Listen string `mapstructure:"listen"` // Default "127.0.0.1"
	Port   int    `mapstructure:"port"`   // Default 60000
	Key    string `mapstructure:"key"`
}

type RegionConfig struct {
	Primary  string   `mapstructure:"primary"`
	Fallback []string `mapstructure:"fallback"`
}

type DatabaseConfig struct {
	Path string `mapstructure:"path"`
}

type DiscoveryConfig struct {
	URL      string `mapstructure:"url"`
	Interval int    `mapstructure:"interval"` // in minutes
}

type ReputationConfig struct {
	Enabled       bool   `mapstructure:"enabled"`
	FailurePolicy string `mapstructure:"failure_policy"` // "conservative" (default) or "lenient"
	AbuseIPDBKey  string `mapstructure:"abuseipdb_key"`
	GreyNoiseKey  string `mapstructure:"greynoise_key"`
	IPQSKey       string `mapstructure:"ipqs_key"`
	IPInfoKey     string `mapstructure:"ipinfo_key"`
	APIKey        string `mapstructure:"api_key"` // backward-compatible alias for AbuseIPDB
}

type ScoringConfig struct {
	VPNPenalty     int     `mapstructure:"vpn_penalty"`     // default 5
	TorPenalty     int     `mapstructure:"tor_penalty"`     // default 50
	HostingPenalty int     `mapstructure:"hosting_penalty"` // default 10
	PrefixBadLimit int     `mapstructure:"prefix_bad_limit"`// default 3 bad IPs
	PrefixPenalty  int     `mapstructure:"prefix_penalty"`  // default 20
	FailurePenalty int     `mapstructure:"failure_penalty"` // default 30 per fail
	SpeedWeight    float64 `mapstructure:"speed_weight"`    // default 1.0
	LatencyWeight  float64 `mapstructure:"latency_weight"`  // default 0.5
}

type SpeedTestConfig struct {
	Enabled      bool     `mapstructure:"enabled"`
	RTTTargetURL string   `mapstructure:"rtt_target_url"`
	DownloadURL  string   `mapstructure:"download_url"`
	UploadURL    string   `mapstructure:"upload_url"`
	TimeoutSec   int      `mapstructure:"timeout_sec"`
	PingTargets  []string `mapstructure:"ping_targets"` // configurable ICMP ping targets
}

// LoadConfig loads the configuration from file and environment variables
func LoadConfig(path string) (*Config, error) {
	viper.SetConfigFile(path)
	viper.SetConfigType("yaml")
	
	// Default settings
	viper.SetDefault("database.path", "xray_manager.db")
	viper.SetDefault("discovery.url", "http://www.vpngate.net/api/iphone/")
	viper.SetDefault("discovery.interval", 15)
	viper.SetDefault("api.listen", "127.0.0.1")
	viper.SetDefault("api.port", 60000)
	viper.SetDefault("reputation.failure_policy", "conservative")
	viper.SetDefault("scoring.vpn_penalty", 5)
	viper.SetDefault("scoring.tor_penalty", 50)
	viper.SetDefault("scoring.hosting_penalty", 10)
	viper.SetDefault("scoring.prefix_bad_limit", 3)
	viper.SetDefault("scoring.prefix_penalty", 20)
	viper.SetDefault("scoring.failure_penalty", 30)
	viper.SetDefault("scoring.speed_weight", 1.0)
	viper.SetDefault("scoring.latency_weight", 0.5)
	viper.SetDefault("speed_test.enabled", true)
	viper.SetDefault("speed_test.rtt_target_url", "https://1.1.1.1")
	viper.SetDefault("speed_test.download_url", "https://speed.cloudflare.com/__down?bytes=5000000")
	viper.SetDefault("speed_test.upload_url", "https://speed.cloudflare.com/__up")
	viper.SetDefault("speed_test.timeout_sec", 15)
	viper.SetDefault("speed_test.ping_targets", []string{"1.1.1.1", "8.8.8.8"})
	viper.SetDefault("xray.vless.enabled", false)
	viper.SetDefault("xray.vless.port", xray.DefaultVlessPublicPort)
	viper.SetDefault("xray.vless.flow", xray.DefaultFlow)
	viper.SetDefault("xray.vless.dest", xray.DefaultRealityTarget)
	viper.SetDefault("xray.vless.server_names", []string{xray.DefaultRealitySNI})
	viper.SetDefault("xray.vless.fingerprint", xray.DefaultRealityFP)
	viper.SetDefault("xray.vless.outbound_only_443", true)
	viper.SetDefault("xray.vless.only_port_443", true)

	viper.SetEnvPrefix("XRAY_MANAGER")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	var cfg Config
	if err := viper.ReadInConfig(); err != nil {
		// It's okay if config file doesn't exist, we can rely on defaults/env
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	err := viper.Unmarshal(&cfg)
	if err != nil {
		return nil, err
	}

	// Validate config fail-fast
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// Validate performs strict startup validation on the loaded configuration.
// It fails fast if ports, URLs, timeouts, or routing parameters are invalid.
func (c *Config) Validate() error {
	// 1. API validation
	if c.API.Port <= 0 || c.API.Port > 65535 {
		return fmt.Errorf("invalid api.port: %d (must be 1-65535)", c.API.Port)
	}
	if strings.TrimSpace(c.API.Listen) == "" {
		return fmt.Errorf("api.listen cannot be empty")
	}
	if net.ParseIP(strings.Trim(c.API.Listen, "[]")) == nil && c.API.Listen != "localhost" {
		return fmt.Errorf("invalid api.listen address: %q", c.API.Listen)
	}

	// 2. Database path validation
	if strings.TrimSpace(c.Database.Path) == "" {
		return fmt.Errorf("database.path cannot be empty")
	}

	// 3. Discovery validation
	if c.Discovery.Interval <= 0 {
		return fmt.Errorf("invalid discovery.interval: %d (must be > 0)", c.Discovery.Interval)
	}
	if strings.TrimSpace(c.Discovery.URL) != "" {
		u, err := url.Parse(c.Discovery.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("invalid discovery.url: %q (must be valid http or https URL)", c.Discovery.URL)
		}
	}

	// 4. Reputation failure policy validation
	if c.Reputation.FailurePolicy != "" && c.Reputation.FailurePolicy != "conservative" && c.Reputation.FailurePolicy != "lenient" {
		return fmt.Errorf("invalid reputation.failure_policy: %q (must be 'conservative' or 'lenient')", c.Reputation.FailurePolicy)
	}

	// 5. Benchmark / SpeedTest validation
	if c.SpeedTest.Enabled {
		if c.SpeedTest.TimeoutSec <= 0 {
			return fmt.Errorf("invalid speed_test.timeout_sec: %d (must be > 0)", c.SpeedTest.TimeoutSec)
		}
		for _, target := range c.SpeedTest.PingTargets {
			target = strings.TrimSpace(target)
			if strings.ContainsAny(target, " \t\n\r;|&`$><(){}[]\"'\\") {
				return fmt.Errorf("invalid characters in speed_test.ping_targets: %q", target)
			}
		}
	}

	// 6. VLESS Reality validation
	if c.Xray.Vless.Enabled {
		if err := xray.ValidatePublicPort(c.Xray.Vless.Port); err != nil {
			return fmt.Errorf("invalid xray.vless.port: %w", err)
		}
		if len(c.Xray.Vless.ServerNames) > 0 {
			if err := xray.ValidateRealitySNI(c.Xray.Vless.ServerNames[0]); err != nil {
				return fmt.Errorf("invalid xray.vless.server_names: %w", err)
			}
		}
		if c.Xray.Vless.Dest != "" {
			expectedSNI := ""
			if len(c.Xray.Vless.ServerNames) > 0 {
				expectedSNI = c.Xray.Vless.ServerNames[0]
			}
			if _, _, err := xray.ValidateRealityDestination(c.Xray.Vless.Dest, expectedSNI); err != nil {
				return fmt.Errorf("invalid xray.vless.dest: %w", err)
			}
		}
	}

	return nil
}

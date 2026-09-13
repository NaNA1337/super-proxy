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
	ConfigPath string           `mapstructure:"config_path"`
	Vless      xray.VlessConfig `mapstructure:"vless"`
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
	Enabled        bool    `mapstructure:"enabled"`
	FailurePolicy  string  `mapstructure:"failure_policy"` // "conservative" (default) or "lenient"
	ProxyCheckKey  string  `mapstructure:"proxycheck_key"`
	ProxyCheckDays float64 `mapstructure:"proxycheck_days"`
	AbuseIPDBKey   string  `mapstructure:"abuseipdb_key"`
	GreyNoiseKey   string  `mapstructure:"greynoise_key"`
	IPQSKey        string  `mapstructure:"ipqs_key"`
	IPInfoKey      string  `mapstructure:"ipinfo_key"`
	APIKey         string  `mapstructure:"api_key"` // backward-compatible alias for AbuseIPDB
}

type ScoringConfig struct {
	ResidentialBonus int     `mapstructure:"residential_bonus"` // default 40
	BusinessBonus    int     `mapstructure:"business_bonus"`    // default 20
	WirelessBonus    int     `mapstructure:"wireless_bonus"`    // default 25
	VPNPenalty       int     `mapstructure:"vpn_penalty"`       // default 5
	TorPenalty       int     `mapstructure:"tor_penalty"`       // default 50
	HostingPenalty   int     `mapstructure:"hosting_penalty"`   // default 10
	PrefixBadLimit   int     `mapstructure:"prefix_bad_limit"`  // default 3 bad IPs
	PrefixPenalty    int     `mapstructure:"prefix_penalty"`    // default 20
	FailurePenalty   int     `mapstructure:"failure_penalty"`   // default 30 per fail
	SpeedWeight      float64 `mapstructure:"speed_weight"`      // default 1.0
	LatencyWeight    float64 `mapstructure:"latency_weight"`    // default 0.5
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
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("yaml")

	// Default settings
	v.SetDefault("database.path", "xray_manager.db")
	v.SetDefault("discovery.url", "http://www.vpngate.net/api/iphone/")
	v.SetDefault("discovery.interval", 15)
	v.SetDefault("api.listen", "127.0.0.1")
	v.SetDefault("api.port", 60000)
	v.SetDefault("reputation.failure_policy", "conservative")
	v.SetDefault("reputation.proxycheck_days", 1.0)
	v.SetDefault("scoring.vpn_penalty", 5)
	v.SetDefault("scoring.residential_bonus", 40)
	v.SetDefault("scoring.business_bonus", 20)
	v.SetDefault("scoring.wireless_bonus", 25)
	v.SetDefault("scoring.tor_penalty", 50)
	v.SetDefault("scoring.hosting_penalty", 10)
	v.SetDefault("scoring.prefix_bad_limit", 3)
	v.SetDefault("scoring.prefix_penalty", 20)
	v.SetDefault("scoring.failure_penalty", 30)
	v.SetDefault("scoring.speed_weight", 1.0)
	v.SetDefault("scoring.latency_weight", 0.5)
	v.SetDefault("speed_test.enabled", true)
	v.SetDefault("speed_test.rtt_target_url", "https://1.1.1.1")
	v.SetDefault("speed_test.download_url", "https://speed.cloudflare.com/__down?bytes=5000000")
	v.SetDefault("speed_test.upload_url", "https://speed.cloudflare.com/__up")
	v.SetDefault("speed_test.timeout_sec", 15)
	v.SetDefault("speed_test.ping_targets", []string{"1.1.1.1", "8.8.8.8"})
	v.SetDefault("xray.vless.enabled", false)
	v.SetDefault("xray.vless.port", xray.DefaultVlessPublicPort)
	v.SetDefault("xray.vless.flow", xray.DefaultFlow)
	v.SetDefault("xray.vless.dest", xray.DefaultRealityTarget)
	v.SetDefault("xray.vless.server_names", []string{xray.DefaultRealitySNI})
	v.SetDefault("xray.vless.fingerprint", xray.DefaultRealityFP)
	v.SetDefault("xray.vless.outbound_only_443", true)
	v.SetDefault("xray.vless.only_port_443", true)

	v.SetEnvPrefix("XRAY_MANAGER")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var cfg Config
	if err := v.ReadInConfig(); err != nil {
		// It's okay if config file doesn't exist, we can rely on defaults/env
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, err
		}
	}

	err := v.Unmarshal(&cfg)
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
	if err := xray.ValidateManagementPort(c.API.Port); err != nil {
		return fmt.Errorf("invalid api.port: %w", err)
	}
	listen := strings.TrimSpace(c.API.Listen)
	if listen == "" {
		return fmt.Errorf("api.listen cannot be empty")
	}
	// Preserve explicit wildcard binds used by remote Manager deployments. The
	// old check passed the untrimmed YAML value to net.ParseIP, so otherwise
	// harmless surrounding whitespace could prevent the entire service from
	// starting. Normalize once and keep IPv6 bracket handling predictable.
	if listen != "localhost" && listen != "0.0.0.0" && listen != "::" && listen != "[::]" &&
		net.ParseIP(strings.Trim(listen, "[]")) == nil {
		return fmt.Errorf("invalid api.listen address: %q", c.API.Listen)
	}
	c.API.Listen = listen

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
	if c.Reputation.ProxyCheckDays < 0.01 || c.Reputation.ProxyCheckDays > 60 {
		return fmt.Errorf("invalid reputation.proxycheck_days: %v (must be between 0.01 and 60)", c.Reputation.ProxyCheckDays)
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
		if err := xray.ValidateVlessPublicPort(c.Xray.Vless.Port); err != nil {
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

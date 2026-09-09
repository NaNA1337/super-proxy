package config

import (
	"strings"

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
	Enabled      bool   `mapstructure:"enabled"`
	RTTTargetURL string `mapstructure:"rtt_target_url"`
	DownloadURL  string `mapstructure:"download_url"`
	UploadURL    string `mapstructure:"upload_url"`
	TimeoutSec   int    `mapstructure:"timeout_sec"`
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
	return &cfg, err
}

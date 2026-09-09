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
	APIKey     string           `mapstructure:"api_key"`
	API        APIConfig        `mapstructure:"api"`
}

type APIConfig struct {
	Key  string `mapstructure:"key"`
	Port int    `mapstructure:"port"`
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
	Enabled bool   `mapstructure:"enabled"`
	APIKey  string `mapstructure:"api_key"` // AbuseIPDB API key
}

// LoadConfig loads the configuration from file and environment variables
func LoadConfig(path string) (*Config, error) {
	viper.SetConfigFile(path)
	viper.SetConfigType("yaml")
	
	// Default settings
	viper.SetDefault("database.path", "xray_manager.db")
	viper.SetDefault("discovery.url", "http://www.vpngate.net/api/iphone/")
	viper.SetDefault("discovery.interval", 15)

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

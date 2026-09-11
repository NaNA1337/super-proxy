package xray

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NaNA1337/super-proxy/internal/routing"
	"github.com/google/uuid"
)

// VlessConfig holds options for configuring a VLESS Reality ingress.
type VlessConfig struct {
	Enabled             bool     `json:"enabled" mapstructure:"enabled"`
	Listen              string   `json:"listen" mapstructure:"listen"`                         // default "0.0.0.0"
	Port                int      `json:"port" mapstructure:"port"`                             // default 443 (strictly TCP/443)
	PublicAddress       string   `json:"public_address,omitempty" mapstructure:"public_address"` // optional explicit public domain/IP
	UUID                string   `json:"uuid" mapstructure:"uuid"`
	Flow                string   `json:"flow" mapstructure:"flow"`                             // default "xtls-rprx-vision"
	Dest                string   `json:"dest" mapstructure:"dest"`                             // default "www.microsoft.com:443"
	ServerNames         []string `json:"server_names" mapstructure:"server_names"`             // default ["www.microsoft.com"]
	PrivateKey          string   `json:"private_key" mapstructure:"private_key"`
	PublicKey           string   `json:"public_key" mapstructure:"public_key"`
	ShortIds            []string `json:"short_ids" mapstructure:"short_ids"`
	Fingerprint         string   `json:"fingerprint" mapstructure:"fingerprint"`               // default "chrome" (uTLS)
	OutboundOnlyPort443 bool     `json:"outbound_only_443" mapstructure:"outbound_only_443"`  // default true (outbound restricted to 443)
	OnlyPort443         bool     `json:"only_port_443,omitempty" mapstructure:"only_port_443"`// backward-compatible alias
}

// ConfigOptions holds options for generating an Xray configuration.
type ConfigOptions struct {
	SlotCount   int
	ConfigPath  string
	ApiPort     int
	SocksListen string
	SocksPort   int
	SocksUser   string
	SocksPass   string
	Redirects   map[int]string // Optional: per-slot destination redirects (used for integration testing exit markers)
	Vless       VlessConfig    // Optional: VLESS + Reality ingress configuration
}

// GenerateX25519Keypair generates an x25519 keypair formatted for Xray Reality (base64 raw URL encoded).
func GenerateX25519Keypair() (privKey, pubKey string, err error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate x25519 key: %w", err)
	}
	privKey = base64.RawURLEncoding.EncodeToString(priv.Bytes())
	pubKey = base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	return privKey, pubKey, nil
}

// GenerateShortID generates an 8-byte hex string for Reality shortId.
func GenerateShortID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// NormalizeVlessConfig applies production defaults and fills missing keys/UUID for VLESS Reality.
func NormalizeVlessConfig(cfg *VlessConfig) error {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	if cfg.Port <= 0 {
		cfg.Port = DefaultVlessPublicPort
	}
	if err := ValidateVlessPublicPort(cfg.Port); err != nil {
		return fmt.Errorf("invalid vless inbound port: %w", err)
	}
	if cfg.Listen == "" {
		cfg.Listen = "0.0.0.0"
	}
	if cfg.UUID == "" {
		cfg.UUID = uuid.New().String()
	} else if _, err := uuid.Parse(cfg.UUID); err != nil {
		return fmt.Errorf("invalid vless UUID %q: %w", cfg.UUID, err)
	}
	if cfg.Flow == "" {
		cfg.Flow = DefaultFlow
	} else if cfg.Flow != DefaultFlow {
		return fmt.Errorf("invalid flow %q: must be %q", cfg.Flow, DefaultFlow)
	}
	if len(cfg.ServerNames) == 0 || cfg.ServerNames[0] == "" {
		cfg.ServerNames = []string{DefaultRealitySNI}
	}
	if err := ValidateRealitySNI(cfg.ServerNames[0]); err != nil {
		return fmt.Errorf("invalid vless SNI: %w", err)
	}
	if cfg.Dest == "" {
		cfg.Dest = DefaultRealityTarget
	}
	if _, _, err := ValidateRealityDestination(cfg.Dest, cfg.ServerNames[0]); err != nil {
		return fmt.Errorf("invalid vless reality destination: %w", err)
	}
	if cfg.Fingerprint == "" {
		cfg.Fingerprint = DefaultRealityFP
	} else if cfg.Fingerprint != DefaultRealityFP {
		return fmt.Errorf("invalid fingerprint %q: must be %q", cfg.Fingerprint, DefaultRealityFP)
	}
	if len(cfg.ShortIds) == 0 || cfg.ShortIds[0] == "" {
		cfg.ShortIds = []string{GenerateShortID()}
	}
	if cfg.PrivateKey == "" || cfg.PublicKey == "" {
		priv, pub, err := GenerateX25519Keypair()
		if err != nil {
			return err
		}
		if cfg.PrivateKey == "" {
			cfg.PrivateKey = priv
		}
		if cfg.PublicKey == "" {
			cfg.PublicKey = pub
		}
	}
	if !cfg.OutboundOnlyPort443 && !cfg.OnlyPort443 {
		cfg.OutboundOnlyPort443 = true
		cfg.OnlyPort443 = true
	} else if cfg.OutboundOnlyPort443 {
		cfg.OnlyPort443 = true
	} else if cfg.OnlyPort443 {
		cfg.OutboundOnlyPort443 = true
	}
	return nil
}

// GenerateConfig generates a static Xray configuration with the specified number of slots
// using Xray's load balancer to ensure connection-level affinity, and enables the internal API.
func GenerateConfig(slotCount int, configPath string) error {
	return GenerateConfigWithOptions(ConfigOptions{
		SlotCount:   slotCount,
		ConfigPath:  configPath,
		ApiPort:     10085,
		SocksListen: "127.0.0.1",
		SocksPort:   1080,
	})
}

// GenerateConfigWithOptions creates an Xray configuration based on ConfigOptions.
func GenerateConfigWithOptions(opts ConfigOptions) error {
	if opts.SlotCount <= 0 {
		opts.SlotCount = 3
	}
	if opts.ApiPort <= 0 {
		opts.ApiPort = 10085
	}
	if opts.SocksListen == "" {
		opts.SocksListen = "127.0.0.1"
	}
	if opts.SocksPort <= 0 {
		opts.SocksPort = 1080
	}

	// Security Hardening: If exposed publicly (0.0.0.0 or external IP), require authentication
	if opts.SocksListen != "127.0.0.1" && opts.SocksListen != "localhost" && opts.SocksUser == "" {
		return fmt.Errorf("security violation: refusing to bind SOCKS to %s without authentication; set socks user/pass to avoid open proxy", opts.SocksListen)
	}

	outbounds := []map[string]interface{}{}
	exitTags := []string{}

	// Add dynamic outbounds for each slot
	for i := 0; i < opts.SlotCount; i++ {
		tag := fmt.Sprintf("exit-%d", i)
		mark := routing.BaseTableID + i

		settings := map[string]interface{}{}
		if opts.Redirects != nil && opts.Redirects[i] != "" {
			settings["redirect"] = opts.Redirects[i]
		}

		outbound := map[string]interface{}{
			"tag":      tag,
			"protocol": "freedom",
			"settings": settings,
			"streamSettings": map[string]interface{}{
				"sockopt": map[string]interface{}{
					"mark": mark, // Binds outbound traffic to Linux policy routing table (BaseTableID + i)
				},
			},
		}
		outbounds = append(outbounds, outbound)
		exitTags = append(exitTags, tag)
	}

	// Add default direct and blackhole outbounds
	outbounds = append(outbounds, map[string]interface{}{
		"tag": "direct", "protocol": "freedom",
	})
	outbounds = append(outbounds, map[string]interface{}{
		"tag": "block", "protocol": "blackhole",
	})

	// Configure SOCKS settings
	socksSettings := map[string]interface{}{
		"auth": "noauth",
		"udp":  true,
	}
	if opts.SocksUser != "" {
		socksSettings["auth"] = "password"
		socksSettings["accounts"] = []map[string]string{
			{
				"user": opts.SocksUser,
				"pass": opts.SocksPass,
			},
		}
	}

	balancers := []map[string]interface{}{
		{
			"tag": "vpn-balancer",
			"selector": []string{
				"exit-", // Matches exit-0, exit-1, exit-2, etc.
			},
			"strategy": map[string]interface{}{
				"type": "random", // Connection-based balancing
			},
		},
	}

	// Generate combination balancers for any subsets of size >= 2
	var generateSubsets func(start int, cur []int)
	generateSubsets = func(start int, cur []int) {
		if len(cur) >= 2 {
			tagParts := make([]string, len(cur))
			selector := make([]string, len(cur))
			for idx, sl := range cur {
				tagParts[idx] = fmt.Sprintf("%d", sl)
				selector[idx] = fmt.Sprintf("exit-%d", sl)
			}
			balancers = append(balancers, map[string]interface{}{
				"tag":      "balancer-" + strings.Join(tagParts, "-"),
				"selector": selector,
				"strategy": map[string]interface{}{
					"type": "random",
				},
			})
		}
		for i := start; i < opts.SlotCount; i++ {
			generateSubsets(i+1, append(cur, i))
		}
	}
	generateSubsets(0, []int{})

	inbounds := []map[string]interface{}{
		{
			"tag":      "api",
			"port":     opts.ApiPort,
			"listen":   "127.0.0.1",
			"protocol": "dokodemo-door",
			"settings": map[string]interface{}{
				"address": "127.0.0.1",
			},
		},
		{
			"tag":      "proxy",
			"port":     opts.SocksPort,
			"listen":   opts.SocksListen,
			"protocol": "socks",
			"settings": socksSettings,
		},
	}

	// Add VLESS Reality Inbound if configured
	if opts.Vless.Enabled {
		if err := NormalizeVlessConfig(&opts.Vless); err != nil {
			return fmt.Errorf("failed to normalize vless config: %w", err)
		}
		vlessInbound := map[string]interface{}{
			"tag":      "vless-in",
			"port":     opts.Vless.Port,
			"listen":   opts.Vless.Listen,
			"protocol": "vless",
			"settings": map[string]interface{}{
				"clients": []map[string]interface{}{
					{
						"id":   opts.Vless.UUID,
						"flow": opts.Vless.Flow,
					},
				},
				"decryption": "none",
			},
			"streamSettings": map[string]interface{}{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]interface{}{
					"show":        false,
					"dest":        opts.Vless.Dest,
					"xver":        0,
					"serverNames": opts.Vless.ServerNames,
					"privateKey":  opts.Vless.PrivateKey,
					"shortIds":    opts.Vless.ShortIds,
				},
			},
		}
		inbounds = append(inbounds, vlessInbound)
	}

	rules := []map[string]interface{}{
		{
			"type":        "field",
			"inboundTag":  []string{"api"},
			"outboundTag": "api",
		},
	}

	if opts.Vless.Enabled {
		if opts.Vless.OutboundOnlyPort443 || opts.Vless.OnlyPort443 {
			// VLESS: port 443 permitted through active proxy exits
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"ruleTag":     "active-balancer-rule-vless",
				"inboundTag":  []string{"vless-in"},
				"port":        "443",
				"outboundTag": "block", // initially block until slot active
			})
			// VLESS: strictly block non-443 outbound destinations
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"ruleTag":     "vless-non-443-block",
				"inboundTag":  []string{"vless-in"},
				"outboundTag": "block",
			})
		} else {
			rules = append(rules, map[string]interface{}{
				"type":        "field",
				"ruleTag":     "active-balancer-rule-vless",
				"inboundTag":  []string{"vless-in"},
				"outboundTag": "block",
			})
		}
	}

	// SOCKS proxy inbound rule (initially block until slot active)
	rules = append(rules, map[string]interface{}{
		"type":        "field",
		"ruleTag":     "active-balancer-rule",
		"inboundTag":  []string{"proxy"},
		"outboundTag": "block",
	})

	// Full Xray configuration with API and Balancers
	xrayConfig := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"api": map[string]interface{}{
			"tag": "api",
			"services": []string{
				"HandlerService",
				"RoutingService",
				"StatsService",
			},
		},
		"stats": map[string]interface{}{},
		"policy": map[string]interface{}{
			"system": map[string]interface{}{
				"statsInboundUplink":    true,
				"statsInboundDownlink":  true,
				"statsOutboundUplink":   true,
				"statsOutboundDownlink": true,
			},
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing": map[string]interface{}{
			"domainStrategy": "AsIs",
			"balancers":      balancers,
			"rules":          rules,
		},
	}

	data, err := json.MarshalIndent(xrayConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal xray config: %w", err)
	}

	if dir := filepath.Dir(opts.ConfigPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return fmt.Errorf("failed to create directory for xray config: %w", err)
		}
	}

	if err := os.WriteFile(opts.ConfigPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write xray config: %w", err)
	}

	return nil
}

package xray

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/NaNA1337/super-proxy/internal/routing"
)

// ConfigOptions holds options for generating an Xray configuration.
type ConfigOptions struct {
	SlotCount   int
	ConfigPath  string
	ApiPort     int
	SocksListen string
	SocksPort   int
	SocksUser   string
	SocksPass   string
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

		outbound := map[string]interface{}{
			"tag":      tag,
			"protocol": "freedom",
			"settings": map[string]interface{}{},
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
		"inbounds": []map[string]interface{}{
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
		},
		"outbounds": outbounds,
		"routing": map[string]interface{}{
			"domainStrategy": "AsIs",
			"balancers":      balancers,
			"rules": []map[string]interface{}{
				{
					"type":        "field",
					"inboundTag":  []string{"api"},
					"outboundTag": "api",
				},
				{
					// Initial outbound state: synchronized to block (blackhole) until tunnels become ACTIVE
					"type":        "field",
					"ruleTag":     "active-balancer-rule",
					"inboundTag":  []string{"proxy"},
					"outboundTag": "block",
				},
			},
		},
	}

	data, err := json.MarshalIndent(xrayConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal xray config: %w", err)
	}

	if err := os.WriteFile(opts.ConfigPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write xray config: %w", err)
	}

	return nil
}

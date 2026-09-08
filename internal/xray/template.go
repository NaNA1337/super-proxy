package xray

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/NaNA1337/super-proxy/internal/routing"
)

// GenerateConfig generates a static Xray configuration with the specified number of slots
// using Xray's load balancer to ensure connection-level affinity.
func GenerateConfig(slotCount int, configPath string) error {
	outbounds := []map[string]interface{}{}
	exitTags := []string{}

	// Add dynamic outbounds for each slot
	for i := 0; i < slotCount; i++ {
		tag := fmt.Sprintf("exit-%d", i)
		mark := routing.BaseTableID + i
		
		outbound := map[string]interface{}{
			"tag":      tag,
			"protocol": "freedom",
			"settings": map[string]interface{}{},
			"streamSettings": map[string]interface{}{
				"sockopt": map[string]interface{}{
					"mark": mark, // This fwmark binds it to the corresponding Linux policy routing table
				},
			},
		}
		outbounds = append(outbounds, outbound)
		exitTags = append(exitTags, tag)
	}

	// Add default direct/block outbounds
	outbounds = append(outbounds, map[string]interface{}{
		"tag": "direct", "protocol": "freedom",
	})
	outbounds = append(outbounds, map[string]interface{}{
		"tag": "block", "protocol": "blackhole",
	})

	// Construct the full Xray configuration
	xrayConfig := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"inbounds": []map[string]interface{}{
			{
				"tag":      "proxy",
				"port":     1080,
				"listen":   "0.0.0.0",
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
			},
		},
		"outbounds": outbounds,
		"routing": map[string]interface{}{
			"domainStrategy": "AsIs",
			"balancers": []map[string]interface{}{
				{
					"tag": "vpn-balancer",
					"selector": []string{
						"exit-", // Matches exit-0, exit-1, exit-2
					},
					"strategy": map[string]interface{}{
						"type": "random", // Xray's balancer is connection-based, not packet-based
					},
				},
			},
			"rules": []map[string]interface{}{
				{
					"type":        "field",
					"network":     "tcp,udp",
					"balancerTag": "vpn-balancer",
				},
			},
		},
	}

	data, err := json.MarshalIndent(xrayConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal xray config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write xray config: %w", err)
	}

	return nil
}

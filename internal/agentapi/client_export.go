package agentapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// VlessClientParams holds the resolved parameters for generating client configurations.
type VlessClientParams struct {
	Address     string `json:"address"`
	Port        int    `json:"port"`
	UUID        string `json:"uuid"`
	Flow        string `json:"flow"`
	SNI         string `json:"sni"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
	ShortID     string `json:"short_id"`
	Tag         string `json:"tag"`
	OnlyPort443 bool   `json:"only_port_443"`
}

// GetVlessClientParams resolves client configuration parameters from active config, env vars, and request context.
func GetVlessClientParams(r *http.Request) (VlessClientParams, bool) {
	cfg := GetActiveVlessConfig()
	enabled := (cfg != nil && cfg.Enabled) || os.Getenv("XRAY_VLESS_ENABLED") == "true"
	if !enabled {
		return VlessClientParams{}, false
	}

	params := VlessClientParams{
		Port:        443,
		Flow:        "xtls-rprx-vision",
		SNI:         "www.microsoft.com",
		Fingerprint: "chrome",
		Tag:         "Super-Proxy-VLESS",
		OnlyPort443: true,
	}

	if cfg != nil {
		if cfg.Port > 0 {
			params.Port = cfg.Port
		}
		if cfg.UUID != "" {
			params.UUID = cfg.UUID
		}
		if cfg.Flow != "" {
			params.Flow = cfg.Flow
		}
		if len(cfg.ServerNames) > 0 && cfg.ServerNames[0] != "" {
			params.SNI = cfg.ServerNames[0]
		}
		if cfg.Fingerprint != "" {
			params.Fingerprint = cfg.Fingerprint
		}
		if cfg.PublicKey != "" {
			params.PublicKey = cfg.PublicKey
		}
		if len(cfg.ShortIds) > 0 && cfg.ShortIds[0] != "" {
			params.ShortID = cfg.ShortIds[0]
		}
	}

	// Environment overrides
	if p, err := strconv.Atoi(os.Getenv("XRAY_VLESS_PORT")); err == nil && p > 0 {
		params.Port = p
	}
	if u := os.Getenv("XRAY_VLESS_UUID"); u != "" {
		params.UUID = u
	}
	if f := os.Getenv("XRAY_VLESS_FLOW"); f != "" {
		params.Flow = f
	}
	if s := os.Getenv("XRAY_VLESS_SNI"); s != "" {
		params.SNI = s
	}
	if fp := os.Getenv("XRAY_VLESS_FINGERPRINT"); fp != "" {
		params.Fingerprint = fp
	}
	if pbk := os.Getenv("XRAY_VLESS_PUBLIC_KEY"); pbk != "" {
		params.PublicKey = pbk
	}
	if sid := os.Getenv("XRAY_VLESS_SHORT_ID"); sid != "" {
		params.ShortID = sid
	}

	// Address resolution: env > query param > request Host > fallback 127.0.0.1
	if addr := os.Getenv("XRAY_VLESS_ADDRESS"); addr != "" {
		params.Address = addr
	} else if r != nil && r.URL.Query().Get("address") != "" {
		params.Address = r.URL.Query().Get("address")
	} else if r != nil && r.Host != "" {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "" && host != "127.0.0.1" && host != "localhost" && host != "::1" {
			params.Address = host
		} else {
			params.Address = "127.0.0.1"
		}
	} else {
		params.Address = "127.0.0.1"
	}

	return params, true
}

// BuildVlessShareLink generates a standard vless:// URI compatible with v2rayN, v2rayNG, Shadowrocket, NekoBox, Karing.
func BuildVlessShareLink(p VlessClientParams) string {
	return fmt.Sprintf("vless://%s@%s:%d?encryption=none&flow=%s&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&type=tcp#%s",
		p.UUID, p.Address, p.Port, p.Flow, p.SNI, p.Fingerprint, p.PublicKey, p.ShortID, url.QueryEscape(p.Tag))
}

// BuildClashMetaProxyItem generates the proxy node structure for Clash Meta / Mihomo.
func BuildClashMetaProxyItem(p VlessClientParams) map[string]interface{} {
	return map[string]interface{}{
		"name":               p.Tag,
		"type":               "vless",
		"server":             p.Address,
		"port":               p.Port,
		"uuid":               p.UUID,
		"network":            "tcp",
		"tls":                true,
		"udp":                true,
		"flow":               p.Flow,
		"servername":         p.SNI,
		"reality-opts": map[string]interface{}{
			"public-key": p.PublicKey,
			"short-id":   p.ShortID,
		},
		"client-fingerprint": p.Fingerprint,
	}
}

// BuildClashMetaProfileYAML generates a complete ready-to-use profile for Clash Meta / Mihomo.
func BuildClashMetaProfileYAML(p VlessClientParams) ([]byte, error) {
	proxy := BuildClashMetaProxyItem(p)

	profile := map[string]interface{}{
		"port":       7890,
		"socks-port": 7891,
		"mixed-port": 7892,
		"allow-lan":  false,
		"mode":       "rule",
		"log-level":  "info",
		"ipv6":       false,
		"dns": map[string]interface{}{
			"enable":        true,
			"listen":        "0.0.0.0:1053",
			"enhanced-mode": "fake-ip",
			"nameserver": []string{
				"223.5.5.5",
				"119.29.29.29",
				"1.1.1.1",
			},
		},
		"proxies": []interface{}{
			proxy,
		},
		"proxy-groups": []map[string]interface{}{
			{
				"name": "PROXY",
				"type": "select",
				"proxies": []string{
					p.Tag,
					"DIRECT",
				},
			},
		},
		"rules": []string{
			"MATCH,PROXY",
		},
	}

	return yaml.Marshal(profile)
}

// BuildSingboxOutboundItem generates the outbound structure for Sing-box.
func BuildSingboxOutboundItem(p VlessClientParams) map[string]interface{} {
	return map[string]interface{}{
		"type":        "vless",
		"tag":         "proxy",
		"server":      p.Address,
		"server_port": p.Port,
		"uuid":        p.UUID,
		"flow":        p.Flow,
		"network":     "tcp",
		"tls": map[string]interface{}{
			"enabled":     true,
			"server_name": p.SNI,
			"utls": map[string]interface{}{
				"enabled":     true,
				"fingerprint": p.Fingerprint,
			},
			"reality": map[string]interface{}{
				"enabled":    true,
				"public_key": p.PublicKey,
				"short_id":   p.ShortID,
			},
		},
		"packet_encoding": "xudp",
	}
}

// BuildSingboxProfileJSON generates a complete ready-to-use configuration for Sing-box.
func BuildSingboxProfileJSON(p VlessClientParams) map[string]interface{} {
	return map[string]interface{}{
		"log": map[string]interface{}{
			"level":     "info",
			"timestamp": true,
		},
		"dns": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"tag":     "remote-dns",
					"address": "tls://1.1.1.1",
					"detour":  "proxy",
				},
				{
					"tag":     "local-dns",
					"address": "223.5.5.5",
					"detour":  "direct",
				},
			},
		},
		"inbounds": []map[string]interface{}{
			{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      "127.0.0.1",
				"listen_port": 2080,
			},
		},
		"outbounds": []interface{}{
			BuildSingboxOutboundItem(p),
			map[string]interface{}{
				"type": "direct",
				"tag":  "direct",
			},
			map[string]interface{}{
				"type": "block",
				"tag":  "block",
			},
		},
		"route": map[string]interface{}{
			"auto_detect_interface": true,
			"final":                 "proxy",
		},
	}
}

// BuildXrayClientConfig generates a complete native Xray-core client configuration.
func BuildXrayClientConfig(p VlessClientParams) map[string]interface{} {
	return map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "warning",
		},
		"inbounds": []map[string]interface{}{
			{
				"port":     10808,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				"settings": map[string]interface{}{
					"auth": "noauth",
					"udp":  true,
				},
				"tag": "socks-in",
			},
			{
				"port":     10809,
				"listen":   "127.0.0.1",
				"protocol": "http",
				"tag":      "http-in",
			},
		},
		"outbounds": []map[string]interface{}{
			{
				"protocol": "vless",
				"settings": map[string]interface{}{
					"vnext": []map[string]interface{}{
						{
							"address": p.Address,
							"port":    p.Port,
							"users": []map[string]interface{}{
								{
									"id":         p.UUID,
									"flow":       p.Flow,
									"encryption": "none",
								},
							},
						},
					},
				},
				"streamSettings": map[string]interface{}{
					"network":  "tcp",
					"security": "reality",
					"realitySettings": map[string]interface{}{
						"show":        false,
						"fingerprint": p.Fingerprint,
						"serverName":  p.SNI,
						"publicKey":   p.PublicKey,
						"shortId":     p.ShortID,
						"spiderX":     "",
					},
				},
				"tag": "proxy",
			},
			{
				"protocol": "freedom",
				"tag":      "direct",
			},
		},
		"routing": map[string]interface{}{
			"domainStrategy": "AsIs",
			"rules": []map[string]interface{}{
				{
					"type":        "field",
					"outboundTag": "proxy",
					"network":     "tcp,udp",
				},
			},
		},
	}
}

// BuildSubscription generates a base64 encoded subscription format.
func BuildSubscription(p VlessClientParams) string {
	link := BuildVlessShareLink(p)
	return base64.StdEncoding.EncodeToString([]byte(link + "\n"))
}

// HTTP Handler: /api/v1/export/clash
func handleExportClash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	params, ok := GetVlessClientParams(r)
	if !ok {
		http.Error(w, "VLESS is not enabled", http.StatusNotFound)
		return
	}
	data, err := BuildClashMetaProfileYAML(params)
	if err != nil {
		http.Error(w, "Failed to generate Clash config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"super-proxy-clash.yaml\"")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// HTTP Handler: /api/v1/export/singbox
func handleExportSingbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	params, ok := GetVlessClientParams(r)
	if !ok {
		http.Error(w, "VLESS is not enabled", http.StatusNotFound)
		return
	}
	profile := BuildSingboxProfileJSON(params)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"super-proxy-singbox.json\"")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(profile)
}

// HTTP Handler: /api/v1/export/xray
func handleExportXray(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	params, ok := GetVlessClientParams(r)
	if !ok {
		http.Error(w, "VLESS is not enabled", http.StatusNotFound)
		return
	}
	profile := BuildXrayClientConfig(params)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"super-proxy-xray.json\"")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(profile)
}

// HTTP Handler: /api/v1/export/sub
func handleExportSub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	params, ok := GetVlessClientParams(r)
	if !ok {
		http.Error(w, "VLESS is not enabled", http.StatusNotFound)
		return
	}
	sub := BuildSubscription(params)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(sub))
}

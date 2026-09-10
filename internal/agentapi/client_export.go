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

	"github.com/NaNA1337/super-proxy/internal/xray"
	"gopkg.in/yaml.v3"
)

// BuildRealityClientProfile resolves and verifies all parameters needed for client export.
// The public port and address are sourced strictly from the active Xray runtime or verified config.
// It enforces that 60000 <= port <= 61000 and NEVER falls back to 443.
func BuildRealityClientProfile(r *http.Request) (*xray.RealityClientProfile, error) {
	cfg := GetActiveVlessConfig()
	enabled := (cfg != nil && cfg.Enabled) || os.Getenv("XRAY_VLESS_ENABLED") == "true"
	if !enabled {
		return nil, fmt.Errorf("VLESS Reality is not enabled on this server")
	}

	profile := &xray.RealityClientProfile{
		Flow:          xray.DefaultFlow,
		Security:      xray.DefaultSecurity,
		Fingerprint:   xray.DefaultRealityFP,
		SNI:           xray.DefaultRealitySNI,
		RealityTarget: xray.DefaultRealityTarget,
		Tag:           "Super-Proxy-VLESS",
	}

	// 1. Sourced from Runtime Endpoint or verified active configuration
	var resolvedPort int
	var resolvedAddr string

	rtEndpoint, err := xray.GetRuntimeVlessEndpoint()
	if err == nil && rtEndpoint != nil {
		resolvedPort = rtEndpoint.Port
		if rtEndpoint.Address != "" && rtEndpoint.Address != "0.0.0.0" {
			resolvedAddr = rtEndpoint.Address
		}
	}

	// If runtime endpoint port not yet set, inspect active config
	if resolvedPort <= 0 && cfg != nil && cfg.Port > 0 {
		resolvedPort = cfg.Port
	}

	// Allow environment override if valid
	if envPortStr := os.Getenv("XRAY_VLESS_PORT"); envPortStr != "" {
		if p, parseErr := strconv.Atoi(envPortStr); parseErr == nil && p > 0 {
			resolvedPort = p
		}
	}

	// Strictly validate the public port - NEVER fallback to 443
	if err := xray.ValidatePublicPort(resolvedPort); err != nil {
		return nil, fmt.Errorf("runtime public port validation failed: %w", err)
	}
	profile.Port = resolvedPort

	// 2. Resolve public address: env > query param > request Host > runtime address > 127.0.0.1
	if envAddr := os.Getenv("XRAY_VLESS_ADDRESS"); envAddr != "" {
		resolvedAddr = envAddr
	} else if r != nil && r.URL.Query().Get("address") != "" {
		resolvedAddr = r.URL.Query().Get("address")
	} else if r != nil && r.Host != "" {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "" && host != "127.0.0.1" && host != "localhost" && host != "::1" {
			resolvedAddr = host
		}
	}
	if resolvedAddr == "" {
		resolvedAddr = "127.0.0.1"
	}
	profile.Address = resolvedAddr

	// 3. Resolve cryptographic credentials & identifiers
	if cfg != nil {
		profile.UUID = cfg.UUID
		profile.PublicKey = cfg.PublicKey
		if len(cfg.ShortIds) > 0 {
			profile.ShortID = cfg.ShortIds[0]
		}
		if len(cfg.ServerNames) > 0 && cfg.ServerNames[0] != "" {
			profile.SNI = cfg.ServerNames[0]
		}
		if cfg.Dest != "" {
			profile.RealityTarget = cfg.Dest
		}
		profile.OutboundOnly443 = cfg.OutboundOnlyPort443 || cfg.OnlyPort443
	}

	// Environment overrides
	if u := os.Getenv("XRAY_VLESS_UUID"); u != "" {
		profile.UUID = u
	}
	if pbk := os.Getenv("XRAY_VLESS_PUBLIC_KEY"); pbk != "" {
		profile.PublicKey = pbk
	}
	if sid := os.Getenv("XRAY_VLESS_SHORT_ID"); sid != "" {
		profile.ShortID = sid
	}
	if s := os.Getenv("XRAY_VLESS_SNI"); s != "" {
		profile.SNI = s
		// Keep RealityTarget in sync with SNI hostname
		profile.RealityTarget = net.JoinHostPort(s, "443")
	}

	// 4. Perform strict validation on the completed profile
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("invalid reality profile: %w", err)
	}

	return profile, nil
}

// BuildVlessShareLink generates a standard vless:// URI compatible with all compliant clients.
// Uses net.JoinHostPort and url.URL to guarantee standard-compliant escaping.
func BuildVlessShareLink(p *xray.RealityClientProfile) (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}

	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("flow", p.Flow)
	q.Set("security", p.Security)
	q.Set("sni", p.SNI)
	q.Set("fp", p.Fingerprint)
	q.Set("pbk", p.PublicKey)
	q.Set("sid", p.ShortID)
	q.Set("type", "tcp")

	u := &url.URL{
		Scheme:   "vless",
		User:     url.User(p.UUID),
		Host:     net.JoinHostPort(p.Address, strconv.Itoa(p.Port)),
		RawQuery: q.Encode(),
		Fragment: p.Tag,
	}

	return u.String(), nil
}

// BuildClashMetaProxyItem generates the proxy node structure for Clash Meta / Mihomo.
func BuildClashMetaProxyItem(p *xray.RealityClientProfile) (map[string]interface{}, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

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
	}, nil
}

// BuildClashMetaProfileYAML generates a complete ready-to-use profile for Clash Meta / Mihomo.
func BuildClashMetaProfileYAML(p *xray.RealityClientProfile) ([]byte, error) {
	proxy, err := BuildClashMetaProxyItem(p)
	if err != nil {
		return nil, err
	}

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
func BuildSingboxOutboundItem(p *xray.RealityClientProfile) (map[string]interface{}, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

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
	}, nil
}

// BuildSingboxProfileJSON generates a complete ready-to-use configuration for Sing-box.
func BuildSingboxProfileJSON(p *xray.RealityClientProfile) (map[string]interface{}, error) {
	outbound, err := BuildSingboxOutboundItem(p)
	if err != nil {
		return nil, err
	}

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
			outbound,
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
	}, nil
}

// BuildXrayClientConfig generates a complete native Xray-core client configuration.
func BuildXrayClientConfig(p *xray.RealityClientProfile) (map[string]interface{}, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}

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
	}, nil
}

// BuildSubscription generates a standard base64 encoded subscription format.
func BuildSubscription(p *xray.RealityClientProfile) (string, error) {
	link, err := BuildVlessShareLink(p)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString([]byte(link + "\n")), nil
}

// HTTP Handler: /api/v1/export/clash
func handleExportClash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	profile, err := BuildRealityClientProfile(r)
	if err != nil {
		http.Error(w, "Client export unavailable: "+err.Error(), http.StatusBadRequest)
		return
	}
	data, err := BuildClashMetaProfileYAML(profile)
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
	profile, err := BuildRealityClientProfile(r)
	if err != nil {
		http.Error(w, "Client export unavailable: "+err.Error(), http.StatusBadRequest)
		return
	}
	sbConfig, err := BuildSingboxProfileJSON(profile)
	if err != nil {
		http.Error(w, "Failed to generate Singbox config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"super-proxy-singbox.json\"")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(sbConfig)
}

// HTTP Handler: /api/v1/export/xray
func handleExportXray(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	profile, err := BuildRealityClientProfile(r)
	if err != nil {
		http.Error(w, "Client export unavailable: "+err.Error(), http.StatusBadRequest)
		return
	}
	xrayConfig, err := BuildXrayClientConfig(profile)
	if err != nil {
		http.Error(w, "Failed to generate Xray config: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"super-proxy-xray.json\"")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(xrayConfig)
}

// HTTP Handler: /api/v1/export/sub
func handleExportSub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	profile, err := BuildRealityClientProfile(r)
	if err != nil {
		http.Error(w, "Subscription unavailable: "+err.Error(), http.StatusBadRequest)
		return
	}
	sub, err := BuildSubscription(profile)
	if err != nil {
		http.Error(w, "Failed to build subscription: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(sub))
}

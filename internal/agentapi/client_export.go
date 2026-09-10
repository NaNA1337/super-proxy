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
	"time"

	"github.com/NaNA1337/super-proxy/internal/xray"
	"gopkg.in/yaml.v3"
)

// BuildRealityClientProfile resolves and verifies all parameters needed for client export.
// The public port and address are sourced strictly from the active running Xray runtime endpoint.
// Fails closed if the runtime endpoint is unavailable (stopped, crashed, or not ready).
// It enforces that public port is strictly 443 and rejects localhost/loopback addresses.
func BuildRealityClientProfile(r *http.Request) (*xray.RealityClientProfile, error) {
	cfg := GetActiveVlessConfig()
	enabled := (cfg != nil && cfg.Enabled) || os.Getenv("XRAY_VLESS_ENABLED") == "true"
	if !enabled {
		return nil, fmt.Errorf("VLESS Reality is not enabled on this server")
	}

	// 1. Sourced strictly from verified active Runtime Endpoint!
	// Fail-closed: absolutely no theoretical endpoint or config/env fallback.
	rtEndpoint, err := xray.GetRuntimeVlessEndpoint()
	if err != nil || rtEndpoint == nil {
		return nil, fmt.Errorf("active Xray runtime endpoint is unavailable: %w", err)
	}

	// Validate runtime public port (strictly 443)
	if err := xray.ValidateVlessPublicPort(rtEndpoint.Port); err != nil {
		return nil, fmt.Errorf("runtime public port validation failed: %w", err)
	}

	// Invariant 9: Enforce active configuration consistency with runtime endpoint
	if cfg != nil {
		if cfg.Port != 0 && cfg.Port != rtEndpoint.Port {
			return nil, fmt.Errorf("active config port %d does not match runtime endpoint port %d", cfg.Port, rtEndpoint.Port)
		}
		if cfg.Flow != "" && cfg.Flow != xray.DefaultFlow {
			return nil, fmt.Errorf("active config flow %q does not match required %q", cfg.Flow, xray.DefaultFlow)
		}
		if cfg.Fingerprint != "" && cfg.Fingerprint != xray.DefaultRealityFP {
			return nil, fmt.Errorf("active config fingerprint %q does not match required %q", cfg.Fingerprint, xray.DefaultRealityFP)
		}
		if len(cfg.ServerNames) > 0 && cfg.ServerNames[0] != "" && cfg.ServerNames[0] != xray.DefaultRealitySNI {
			return nil, fmt.Errorf("active config SNI %q does not match required %q", cfg.ServerNames[0], xray.DefaultRealitySNI)
		}
		if cfg.Dest != "" && cfg.Dest != xray.DefaultRealityTarget {
			return nil, fmt.Errorf("active config dest %q does not match required %q", cfg.Dest, xray.DefaultRealityTarget)
		}
	}

	profile := &xray.RealityClientProfile{
		Port:          rtEndpoint.Port,
		Flow:          xray.DefaultFlow,
		Security:      xray.DefaultSecurity,
		Fingerprint:   xray.DefaultRealityFP,
		SNI:           xray.DefaultRealitySNI,
		RealityTarget: xray.DefaultRealityTarget,
		Tag:           "Super-Proxy-VLESS",
	}

	// 2. Resolve public address:
	// Preference: query param (?address=...) > runtime address > request Host > env (XRAY_VLESS_ADDRESS)
	// Strictly NO localhost or 127.0.0.1 fallback!
	var resolvedAddr string
	if r != nil && r.URL != nil && r.URL.Query().Get("address") != "" {
		reqAddr := r.URL.Query().Get("address")
		if err := xray.ValidatePublicAddress(reqAddr); err != nil {
			return nil, fmt.Errorf("cannot determine valid public client address (localhost/127.0.0.1 is prohibited): %w", err)
		}
		resolvedAddr = reqAddr
	} else if rtEndpoint.Address != "" && rtEndpoint.Address != "0.0.0.0" {
		if err := xray.ValidatePublicAddress(rtEndpoint.Address); err == nil {
			resolvedAddr = rtEndpoint.Address
		}
	} else if r != nil && r.Host != "" {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if err := xray.ValidatePublicAddress(host); err == nil {
			resolvedAddr = host
		}
	}

	if resolvedAddr == "" {
		if envAddr := os.Getenv("XRAY_VLESS_ADDRESS"); envAddr != "" {
			if err := xray.ValidatePublicAddress(envAddr); err == nil {
				resolvedAddr = envAddr
			}
		}
	}

	// Strict public address validation: rejects localhost, 127.0.0.1, 0.0.0.0, ::1, empty
	if err := xray.ValidatePublicAddress(resolvedAddr); err != nil {
		return nil, fmt.Errorf("cannot determine valid public client address (localhost/127.0.0.1 is prohibited): %w", err)
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

// NodeInfo describes the egress node identifying information.
type NodeInfo struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Region  string `json:"region"`
	Country string `json:"country"`
	Status  string `json:"status,omitempty"`
}

// EndpointInfo describes the public client ingress endpoint.
type EndpointInfo struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Network  string `json:"network"`
	Protocol string `json:"protocol"`
	TLS      bool   `json:"tls"`
}

// RealityInfo describes the active Reality parameters for client connection.
type RealityInfo struct {
	ServerName  string `json:"server_name"`
	Fingerprint string `json:"fingerprint"`
	Flow        string `json:"flow"`
	Destination string `json:"destination"`
}

// ClientProfileItem contains the rendered export for a specific client format.
type ClientProfileItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Format   string `json:"format"`
	MimeType string `json:"mime_type"`
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

// ClientConfigBundle is the unified canonical bundle containing all client configurations.
type ClientConfigBundle struct {
	SchemaVersion int                 `json:"schema_version"`
	GeneratedAt   string              `json:"generated_at"`
	Node          NodeInfo            `json:"node"`
	Endpoint      EndpointInfo        `json:"endpoint"`
	Reality       RealityInfo         `json:"reality"`
	Profiles      []ClientProfileItem `json:"profiles"`
}

// BuildClientConfigBundle builds the unified client configuration bundle.
// It is the single source of truth for /api/v1/client-config/all and all client export endpoints.
// Fails closed immediately if runtime endpoint is unavailable or active config is inconsistent.
func BuildClientConfigBundle(r *http.Request) (*ClientConfigBundle, error) {
	profile, err := BuildRealityClientProfile(r)
	if err != nil {
		return nil, err
	}

	// Double-check consistency invariants on runtime profile
	if profile.Port != 443 {
		return nil, fmt.Errorf("runtime client endpoint port must be 443, got %d", profile.Port)
	}
	if profile.Flow != xray.DefaultFlow {
		return nil, fmt.Errorf("runtime client flow %q does not match required %q", profile.Flow, xray.DefaultFlow)
	}
	if profile.Fingerprint != xray.DefaultRealityFP {
		return nil, fmt.Errorf("runtime client fingerprint %q does not match required %q", profile.Fingerprint, xray.DefaultRealityFP)
	}
	if profile.SNI != xray.DefaultRealitySNI {
		return nil, fmt.Errorf("runtime client SNI %q does not match required %q", profile.SNI, xray.DefaultRealitySNI)
	}
	if profile.RealityTarget != xray.DefaultRealityTarget {
		return nil, fmt.Errorf("runtime client destination %q does not match required %q", profile.RealityTarget, xray.DefaultRealityTarget)
	}
	if err := xray.ValidatePublicAddress(profile.Address); err != nil {
		return nil, fmt.Errorf("runtime client address is invalid: %w", err)
	}

	// 1. VLESS URI
	vlessURI, err := BuildVlessShareLink(profile)
	if err != nil {
		return nil, fmt.Errorf("failed to generate VLESS URI: %w", err)
	}

	// 2. Clash Meta YAML
	clashYAML, err := BuildClashMetaProfileYAML(profile)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Clash Meta profile: %w", err)
	}

	// 3. Sing-box JSON
	singboxMap, err := BuildSingboxProfileJSON(profile)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Singbox profile: %w", err)
	}
	singboxJSON, err := json.MarshalIndent(singboxMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Singbox JSON: %w", err)
	}

	// 4. Xray-core JSON
	xrayMap, err := BuildXrayClientConfig(profile)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Xray config: %w", err)
	}
	xrayJSON, err := json.MarshalIndent(xrayMap, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Xray JSON: %w", err)
	}

	// 5. Subscription (Base64)
	subBase64, err := BuildSubscription(profile)
	if err != nil {
		return nil, fmt.Errorf("failed to generate subscription: %w", err)
	}

	// Resolve node metadata without duplicating storage
	nodeID, _ := os.Hostname()
	if nodeID == "" {
		nodeID = "super-proxy-node"
	}
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName = "Super-Proxy Egress Node"
	}
	nodeRegion := os.Getenv("XRAY_MANAGER_REGION")
	if nodeRegion == "" && sched != nil && sched.RegionConfig.Primary != "" {
		nodeRegion = sched.RegionConfig.Primary
	}
	if nodeRegion == "" {
		nodeRegion = "JP"
	}
	nodeCountry := os.Getenv("XRAY_MANAGER_COUNTRY")
	if nodeCountry == "" {
		nodeCountry = nodeRegion
	}

	bundle := &ClientConfigBundle{
		SchemaVersion: 1,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Node: NodeInfo{
			ID:      nodeID,
			Name:    nodeName,
			Region:  nodeRegion,
			Country: nodeCountry,
			Status:  "online",
		},
		Endpoint: EndpointInfo{
			Address:  profile.Address,
			Port:     profile.Port,
			Network:  "tcp",
			Protocol: "vless",
			TLS:      true,
		},
		Reality: RealityInfo{
			ServerName:  profile.SNI,
			Fingerprint: profile.Fingerprint,
			Flow:        profile.Flow,
			Destination: profile.RealityTarget,
		},
		Profiles: []ClientProfileItem{
			{
				ID:       "vless",
				Name:     "VLESS",
				Format:   "uri",
				MimeType: "text/plain",
				Filename: "vless.txt",
				Content:  vlessURI,
			},
			{
				ID:       "clash-meta",
				Name:     "Clash Meta",
				Format:   "yaml",
				MimeType: "application/yaml",
				Filename: "clash-meta.yaml",
				Content:  string(clashYAML),
			},
			{
				ID:       "sing-box",
				Name:     "sing-box",
				Format:   "json",
				MimeType: "application/json",
				Filename: "sing-box.json",
				Content:  string(singboxJSON),
			},
			{
				ID:       "xray",
				Name:     "Xray",
				Format:   "json",
				MimeType: "application/json",
				Filename: "xray.json",
				Content:  string(xrayJSON),
			},
			{
				ID:       "subscription",
				Name:     "Base64 Subscription",
				Format:   "base64",
				MimeType: "text/plain",
				Filename: "subscription.txt",
				Content:  subBase64,
			},
		},
	}

	return bundle, nil
}

// HTTP Handler: /api/v1/export/clash
func handleExportClash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	bundle, err := BuildClientConfigBundle(r)
	if err != nil {
		http.Error(w, "Client export unavailable: "+err.Error(), http.StatusBadRequest)
		return
	}
	for _, p := range bundle.Profiles {
		if p.ID == "clash-meta" {
			w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
			w.Header().Set("Content-Disposition", "attachment; filename=\"super-proxy-clash.yaml\"")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(p.Content))
			return
		}
	}
	http.Error(w, "Clash profile not found in bundle", http.StatusInternalServerError)
}

// HTTP Handler: /api/v1/export/singbox
func handleExportSingbox(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	bundle, err := BuildClientConfigBundle(r)
	if err != nil {
		http.Error(w, "Client export unavailable: "+err.Error(), http.StatusBadRequest)
		return
	}
	for _, p := range bundle.Profiles {
		if p.ID == "sing-box" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Content-Disposition", "attachment; filename=\"super-proxy-singbox.json\"")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(p.Content + "\n"))
			return
		}
	}
	http.Error(w, "Sing-box profile not found in bundle", http.StatusInternalServerError)
}

// HTTP Handler: /api/v1/export/xray
func handleExportXray(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	bundle, err := BuildClientConfigBundle(r)
	if err != nil {
		http.Error(w, "Client export unavailable: "+err.Error(), http.StatusBadRequest)
		return
	}
	for _, p := range bundle.Profiles {
		if p.ID == "xray" {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Content-Disposition", "attachment; filename=\"super-proxy-xray.json\"")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(p.Content + "\n"))
			return
		}
	}
	http.Error(w, "Xray profile not found in bundle", http.StatusInternalServerError)
}

// HTTP Handler: /api/v1/export/sub
func handleExportSub(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	bundle, err := BuildClientConfigBundle(r)
	if err != nil {
		http.Error(w, "Subscription unavailable: "+err.Error(), http.StatusBadRequest)
		return
	}
	for _, p := range bundle.Profiles {
		if p.ID == "subscription" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(p.Content))
			return
		}
	}
	http.Error(w, "Subscription profile not found in bundle", http.StatusInternalServerError)
}

// HTTP Handler: /api/v1/client-config/all
func handleClientConfigAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	bundle, err := BuildClientConfigBundle(r)
	if err != nil {
		http.Error(w, "runtime client endpoint unavailable: "+err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(bundle)
}

package agentapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/database"
	"github.com/NaNA1337/super-proxy/internal/models"
	"github.com/NaNA1337/super-proxy/internal/reputation"
	"github.com/NaNA1337/super-proxy/internal/scheduler"
	"github.com/NaNA1337/super-proxy/internal/xray"
)

func setupTestServer() http.Handler {
	testKey := "test-secret-api-key-12345"
	InitAuth(testKey)

	sched := scheduler.NewScheduler(3, 2, reputation.NewEngine(), config.RegionConfig{Primary: "JP"})
	SetScheduler(sched)

	mux := http.NewServeMux()
	panicRecoveryMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				}
			}()
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			next.ServeHTTP(w, r)
		})
	}

	secureChain := func(h http.Handler) http.Handler {
		return panicRecoveryMiddleware(rateLimitMiddleware(authMiddleware(h)))
	}

	mux.Handle("/api/v1/status", secureChain(http.HandlerFunc(handleStatus)))
	mux.Handle("/api/v1/slots/", secureChain(http.HandlerFunc(handleSlotAction)))
	mux.Handle("/api/v1/nodes/", secureChain(http.HandlerFunc(handleNodeDetails)))
	mux.Handle("/api/v1/pool/qualified", secureChain(http.HandlerFunc(handlePoolQualified)))
        mux.Handle("/api/v1/nodes", secureChain(http.HandlerFunc(handleNodesList)))
        mux.Handle("/api/v1/routing", secureChain(http.HandlerFunc(handleRoutingOverview)))
        mux.Handle("/api/v1/client-config", secureChain(http.HandlerFunc(handleClientConfig)))
	mux.Handle("/api/v1/export/clash", secureChain(http.HandlerFunc(handleExportClash)))
	mux.Handle("/api/v1/export/singbox", secureChain(http.HandlerFunc(handleExportSingbox)))
	mux.Handle("/api/v1/export/xray", secureChain(http.HandlerFunc(handleExportXray)))
	mux.Handle("/api/v1/export/sub", secureChain(http.HandlerFunc(handleExportSub)))
	mux.Handle("/api/v1/panic", secureChain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("simulated critical crash")
	})))
	return mux
}

func TestAPI_Unauthenticated(t *testing.T) {
	handler := setupTestServer()

	req, _ := http.NewRequest("GET", "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for missing token, got %d", rr.Code)
	}
}

func TestAPI_InvalidToken(t *testing.T) {
	handler := setupTestServer()

	req, _ := http.NewRequest("GET", "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer invalid-wrong-token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for invalid token, got %d", rr.Code)
	}
}

func TestAPI_ValidAuth(t *testing.T) {
	handler := setupTestServer()

	req, _ := http.NewRequest("GET", "/api/v1/status", nil)
	req.Header.Set("Authorization", "Bearer test-secret-api-key-12345")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for valid token, got %d", rr.Code)
	}
}

func TestAPI_RateLimit_Unauthenticated(t *testing.T) {
	handler := setupTestServer()

	// unauthBurst is 10. Sending 15 requests in rapid succession from same remote addr
	// should trigger 429.
	got429 := false
	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", "/api/v1/status", nil)
		req.RemoteAddr = "192.0.2.99:12345"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)

		if rr.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}

	if !got429 {
		t.Fatalf("Expected 429 Too Many Requests after exceeding unauth burst limit")
	}
}

func TestAPI_OversizedBodyBlocked(t *testing.T) {
	handler := setupTestServer()

	// Create 2MB payload (exceeds 1MB MaxBytesReader limit)
	hugePayload := strings.Repeat("x", 2*1024*1024)
	body, _ := json.Marshal(map[string]string{"node_id": hugePayload})

	req, _ := http.NewRequest("POST", "/api/v1/slots/0/switch", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer test-secret-api-key-12345")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request for payload > 1MB, got %d", rr.Code)
	}
}

func TestAPI_PanicRecovery(t *testing.T) {
	handler := setupTestServer()

	req, _ := http.NewRequest("GET", "/api/v1/panic", nil)
	req.Header.Set("Authorization", "Bearer test-secret-api-key-12345")
	rr := httptest.NewRecorder()

	// Should not crash the test suite or process
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("Expected 500 Internal Server Error after panic recovery, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "internal server error") {
		t.Errorf("Expected error message in response body, got: %s", rr.Body.String())
	}
}

func TestAPI_SecretRedaction(t *testing.T) {
	// Initialize in-memory test database
	if err := database.InitDatabase(":memory:"); err != nil {
		t.Fatalf("failed to init db: %v", err)
	}

	secretKey := "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD...LEAK_TEST_KEY...\n-----END PRIVATE KEY-----"
	testNode := models.Node{
		ID:            "198.51.100.200",
		IP:            "198.51.100.200",
		Status:        models.StatusQualified,
		OpenVPN:       "cmF3X2Jhc2U2NF9zZWNyZXRfY29uZmln", // base64
		OpenVPNConfig: "client\ndev tun\n<key>\n" + secretKey + "\n</key>\n",
	}
	if err := database.DB.Create(&testNode).Error; err != nil {
		t.Fatalf("failed to create test node: %v", err)
	}

	handler := setupTestServer()

	// 1. Query Node Details endpoint
	req, _ := http.NewRequest("GET", "/api/v1/nodes/198.51.100.200", nil)
	req.Header.Set("Authorization", "Bearer test-secret-api-key-12345")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}

	bodyStr := rr.Body.String()

	// Verify private key is strictly absent
	if strings.Contains(bodyStr, "LEAK_TEST_KEY") {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Private key leaked in /api/v1/nodes/ response!")
	}
	// Verify raw base64 is strictly absent
	if strings.Contains(bodyStr, "cmF3X2Jhc2U2NF9zZWNyZXRfY29uZmln") {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Raw OpenVPN Base64 leaked in /api/v1/nodes/ response!")
	}
	// Verify redacted placeholder is used instead
	if !strings.Contains(bodyStr, "[PRIVATE KEY REDACTED]") {
		t.Errorf("Expected [PRIVATE KEY REDACTED] placeholder in response, got: %s", bodyStr)
	}
}



func TestAPI_WebManagerSupplementaryEndpoints(t *testing.T) {
	_ = database.InitDatabase(":memory:")
	InitAuth("test-secret-api-key-12345")
	handler := setupTestServer()

	// 1. Test /api/v1/nodes
	req, _ := http.NewRequest("GET", "/api/v1/nodes?country=JP&limit=10", nil)
	req.Header.Set("Authorization", "Bearer test-secret-api-key-12345")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/v1/nodes, got %d: %s", rr.Code, rr.Body.String())
	}

	// 2. Test /api/v1/routing
	req, _ = http.NewRequest("GET", "/api/v1/routing", nil)
	req.Header.Set("Authorization", "Bearer test-secret-api-key-12345")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/v1/routing, got %d: %s", rr.Code, rr.Body.String())
	}

	// 3. Test /api/v1/client-config (with VLESS Reality enabled)
	SetActiveVlessConfig(&xray.VlessConfig{
		Enabled:             true,
		Port:                60001,
		UUID:                "b831381d-6324-4d53-ad4f-8cda48b30811",
		Flow:                "xtls-rprx-vision",
		Dest:                "www.microsoft.com:443",
		ServerNames:         []string{"www.microsoft.com"},
		Fingerprint:         "chrome",
		PublicKey:           "Af0aicE9KbySwRkPTZJrI0PfgEH5g3nydVMA79RGBCg",
		ShortIds:            []string{"0123456789abcdef"},
		OutboundOnlyPort443: true,
	})

	req, _ = http.NewRequest("GET", "/api/v1/client-config", nil)
	req.Header.Set("Authorization", "Bearer test-secret-api-key-12345")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/v1/client-config, got %d: %s", rr.Code, rr.Body.String())
	}
	bodyStr := rr.Body.String()
	if !strings.Contains(bodyStr, "vless") || !strings.Contains(bodyStr, "xtls-rprx-vision") {
		t.Errorf("expected vless and xtls-rprx-vision in client config: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "www.microsoft.com") || !strings.Contains(bodyStr, "chrome") {
		t.Errorf("expected SNI www.microsoft.com and fingerprint chrome in client config: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "vless://") {
		t.Errorf("expected vless share link in client config: %s", bodyStr)
	}
}

func TestAPI_ClientExportEndpoints(t *testing.T) {
	_ = database.InitDatabase(":memory:")
	InitAuth("test-secret-api-key-12345")
	handler := setupTestServer()

	SetActiveVlessConfig(&xray.VlessConfig{
		Enabled:             true,
		Port:                60001,
		UUID:                "b831381d-6324-4d53-ad4f-8cda48b30811",
		Flow:                "xtls-rprx-vision",
		Dest:                "www.microsoft.com:443",
		ServerNames:         []string{"www.microsoft.com"},
		Fingerprint:         "chrome",
		PublicKey:           "Af0aicE9KbySwRkPTZJrI0PfgEH5g3nydVMA79RGBCg",
		ShortIds:            []string{"0123456789abcdef"},
		OutboundOnlyPort443: true,
	})

	// 1. Test /api/v1/export/clash (YAML output)
	req, _ := http.NewRequest("GET", "/api/v1/export/clash", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("Authorization", "Bearer test-secret-api-key-12345")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/v1/export/clash, got %d: %s", rr.Code, rr.Body.String())
	}
	clashYaml := rr.Body.String()
	if !strings.Contains(clashYaml, "type: vless") || !strings.Contains(clashYaml, "reality-opts") {
		t.Errorf("clash yaml missing vless reality fields: %s", clashYaml)
	}
	if !strings.Contains(clashYaml, "flow: xtls-rprx-vision") || !strings.Contains(clashYaml, "client-fingerprint: chrome") {
		t.Errorf("clash yaml missing flow or fingerprint: %s", clashYaml)
	}
	if !strings.Contains(clashYaml, "servername: www.microsoft.com") {
		t.Errorf("clash yaml missing SNI www.microsoft.com: %s", clashYaml)
	}
	if !strings.Contains(clashYaml, "port: 60001") {
		t.Errorf("clash yaml missing port 60001: %s", clashYaml)
	}

	// 2. Test /api/v1/export/singbox (JSON output)
	req, _ = http.NewRequest("GET", "/api/v1/export/singbox", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("Authorization", "Bearer test-secret-api-key-12345")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/v1/export/singbox, got %d: %s", rr.Code, rr.Body.String())
	}
	singboxJson := rr.Body.String()
	if !strings.Contains(singboxJson, "\"type\":\"vless\"") && !strings.Contains(singboxJson, "\"type\": \"vless\"") {
		t.Errorf("singbox json missing vless: %s", singboxJson)
	}
	if !strings.Contains(singboxJson, "reality") || !strings.Contains(singboxJson, "chrome") || !strings.Contains(singboxJson, "www.microsoft.com") {
		t.Errorf("singbox json missing reality/fingerprint/SNI: %s", singboxJson)
	}
	if !strings.Contains(singboxJson, "60001") {
		t.Errorf("singbox json missing port 60001: %s", singboxJson)
	}

	// 3. Test /api/v1/export/xray (JSON output)
	req, _ = http.NewRequest("GET", "/api/v1/export/xray", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	req.Header.Set("Authorization", "Bearer test-secret-api-key-12345")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/v1/export/xray, got %d: %s", rr.Code, rr.Body.String())
	}
	xrayJson := rr.Body.String()
	if (!strings.Contains(xrayJson, "\"protocol\":\"vless\"") && !strings.Contains(xrayJson, "\"protocol\": \"vless\"")) ||
		(!strings.Contains(xrayJson, "\"security\":\"reality\"") && !strings.Contains(xrayJson, "\"security\": \"reality\"")) {
		t.Errorf("xray json missing vless reality: %s", xrayJson)
	}
	if !strings.Contains(xrayJson, "60001") {
		t.Errorf("xray json missing port 60001: %s", xrayJson)
	}

	// 4. Test /api/v1/export/sub with ?token= query auth (standard subscription URL import)
	req, _ = http.NewRequest("GET", "/api/v1/export/sub?token=test-secret-api-key-12345", nil)
	req.RemoteAddr = "192.0.2.10:12345"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on /api/v1/export/sub?token=..., got %d: %s", rr.Code, rr.Body.String())
	}
	subBase64 := strings.TrimSpace(rr.Body.String())
	decoded, err := base64.StdEncoding.DecodeString(subBase64)
	if err != nil {
		t.Fatalf("failed to decode base64 subscription: %v", err)
	}
	if !strings.HasPrefix(string(decoded), "vless://") {
		t.Errorf("expected subscription to decode to vless:// link, got: %s", string(decoded))
	}
	if !strings.Contains(string(decoded), ":60001") {
		t.Errorf("expected subscription link to contain port 60001, got: %s", string(decoded))
	}
}

func TestAPI_ClientExport_RejectsPort443(t *testing.T) {
	InitAuth("test-secret-api-key-12345")
	handler := setupTestServer()

	// Configure VLESS with invalid public port 443
	SetActiveVlessConfig(&xray.VlessConfig{
		Enabled:             true,
		Port:                443, // Strictly forbidden as public client port
		UUID:                "b831381d-6324-4d53-ad4f-8cda48b30811",
		Flow:                "xtls-rprx-vision",
		Dest:                "www.microsoft.com:443",
		ServerNames:         []string{"www.microsoft.com"},
		Fingerprint:         "chrome",
		PublicKey:           "Af0aicE9KbySwRkPTZJrI0PfgEH5g3nydVMA79RGBCg",
		ShortIds:            []string{"0123456789abcdef"},
		OutboundOnlyPort443: true,
	})
	xray.ClearRuntimeVlessEndpoint()

	req, _ := http.NewRequest("GET", "/api/v1/export/clash", nil)
	req.RemoteAddr = "192.0.2.11:12345"
	req.Header.Set("Authorization", "Bearer test-secret-api-key-12345")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request when port 443 is used, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "port") {
		t.Errorf("expected error message to mention port validation, got: %s", rr.Body.String())
	}
}

func TestAPI_ClientExport_UsesRuntimeEndpoint(t *testing.T) {
	InitAuth("test-secret-api-key-12345")
	handler := setupTestServer()

	SetActiveVlessConfig(&xray.VlessConfig{
		Enabled:             true,
		Port:                60001,
		UUID:                "b831381d-6324-4d53-ad4f-8cda48b30811",
		Flow:                "xtls-rprx-vision",
		Dest:                "www.microsoft.com:443",
		ServerNames:         []string{"www.microsoft.com"},
		Fingerprint:         "chrome",
		PublicKey:           "Af0aicE9KbySwRkPTZJrI0PfgEH5g3nydVMA79RGBCg",
		ShortIds:            []string{"0123456789abcdef"},
		OutboundOnlyPort443: true,
	})

	// Register actual runtime endpoint dynamically
	err := xray.SetRuntimeVlessEndpoint(xray.PublicEndpoint{
		Address:  "node-jp-01.super-proxy.net",
		Port:     60088,
		Network:  "tcp",
		TLS:      true,
		Protocol: "vless",
	})
	if err != nil {
		t.Fatalf("failed to set runtime endpoint: %v", err)
	}
	defer xray.ClearRuntimeVlessEndpoint()

	// Query /api/v1/export/clash
	req, _ := http.NewRequest("GET", "/api/v1/export/clash", nil)
	req.RemoteAddr = "192.0.2.12:12345"
	req.Header.Set("Authorization", "Bearer test-secret-api-key-12345")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rr.Code, rr.Body.String())
	}
	clashYaml := rr.Body.String()
	if !strings.Contains(clashYaml, "server: node-jp-01.super-proxy.net") {
		t.Errorf("expected runtime address in clash export, got: %s", clashYaml)
	}
	if !strings.Contains(clashYaml, "port: 60088") {
		t.Errorf("expected runtime port 60088 in clash export, got: %s", clashYaml)
	}
}

func TestAPI_VlessURIRoundTrip(t *testing.T) {
	profile := &xray.RealityClientProfile{
		Address:         "edge-kr.super-proxy.net",
		Port:            60555,
		UUID:            "11111111-2222-3333-4444-555555555555",
		SNI:             "www.microsoft.com",
		Fingerprint:     "chrome",
		PublicKey:       "Af0aicE9KbySwRkPTZJrI0PfgEH5g3nydVMA79RGBCg",
		ShortID:         "0123456789abcdef",
		Flow:            "xtls-rprx-vision",
		Security:        "reality",
		RealityTarget:   "www.microsoft.com:443",
		Tag:             "Tokyo-Exit-01",
		OutboundOnly443: true,
	}

	link, err := BuildVlessShareLink(profile)
	if err != nil {
		t.Fatalf("BuildVlessShareLink failed: %v", err)
	}

	// Parse URI
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatalf("failed to parse generated URI: %v", err)
	}

	if parsed.Scheme != "vless" {
		t.Errorf("expected scheme vless, got: %s", parsed.Scheme)
	}
	if parsed.User == nil || parsed.User.Username() != profile.UUID {
		t.Errorf("expected UUID in userinfo %s, got: %v", profile.UUID, parsed.User)
	}
	if parsed.Hostname() != profile.Address {
		t.Errorf("expected hostname %s, got: %s", profile.Address, parsed.Hostname())
	}
	if parsed.Port() != "60555" {
		t.Errorf("expected port 60555, got: %s", parsed.Port())
	}

	q := parsed.Query()
	if q.Get("flow") != "xtls-rprx-vision" {
		t.Errorf("expected flow xtls-rprx-vision, got: %s", q.Get("flow"))
	}
	if q.Get("security") != "reality" {
		t.Errorf("expected security reality, got: %s", q.Get("security"))
	}
	if q.Get("sni") != "www.microsoft.com" {
		t.Errorf("expected sni www.microsoft.com, got: %s", q.Get("sni"))
	}
	if q.Get("fp") != "chrome" {
		t.Errorf("expected fp chrome, got: %s", q.Get("fp"))
	}
	if q.Get("pbk") != profile.PublicKey {
		t.Errorf("expected pbk %s, got: %s", profile.PublicKey, q.Get("pbk"))
	}
	if q.Get("sid") != profile.ShortID {
		t.Errorf("expected sid %s, got: %s", profile.ShortID, q.Get("sid"))
	}
	if parsed.Fragment != profile.Tag {
		t.Errorf("expected fragment %s, got: %s", profile.Tag, parsed.Fragment)
	}
}

func TestAPI_XrayClientConfigValidationWithBinary(t *testing.T) {
	xrayPath, err := exec.LookPath("xray")
	if err != nil {
		t.Skip("xray binary not available on test host, skipping live validation")
	}

	profile := &xray.RealityClientProfile{
		Address:         "127.0.0.1",
		Port:            60001,
		UUID:            "b831381d-6324-4d53-ad4f-8cda48b30811",
		SNI:             "www.microsoft.com",
		Fingerprint:     "chrome",
		PublicKey:       "Af0aicE9KbySwRkPTZJrI0PfgEH5g3nydVMA79RGBCg",
		ShortID:         "0123456789abcdef",
		Flow:            "xtls-rprx-vision",
		Security:        "reality",
		RealityTarget:   "www.microsoft.com:443",
		Tag:             "Super-Proxy-VLESS",
		OutboundOnly443: true,
	}

	configMap, err := BuildXrayClientConfig(profile)
	if err != nil {
		t.Fatalf("BuildXrayClientConfig failed: %v", err)
	}

	data, err := json.MarshalIndent(configMap, "", "  ")
	if err != nil {
		t.Fatalf("failed to marshal json: %v", err)
	}

	tmpFile := filepath.Join(t.TempDir(), "client_config.json")
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		t.Fatalf("failed to write client config: %v", err)
	}

	cmd := exec.Command(xrayPath, "run", "-test", "-config", tmpFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("xray run -test failed on generated client config: %v\nOutput:\n%s", err, string(out))
	}
}

func TestAPI_SecretRedactionInExports(t *testing.T) {
	privKey := "PRIVATE_KEY_SECRET_SHOULD_NEVER_BE_EXPOSED"
	profile := &xray.RealityClientProfile{
		Address:         "198.51.100.1",
		Port:            60001,
		UUID:            "b831381d-6324-4d53-ad4f-8cda48b30811",
		SNI:             "www.microsoft.com",
		Fingerprint:     "chrome",
		PublicKey:       "Af0aicE9KbySwRkPTZJrI0PfgEH5g3nydVMA79RGBCg",
		ShortID:         "0123456789abcdef",
		Flow:            "xtls-rprx-vision",
		Security:        "reality",
		RealityTarget:   "www.microsoft.com:443",
		Tag:             "Super-Proxy-VLESS",
		OutboundOnly443: true,
	}

	// 1. Clash
	clashYamlBytes, err := BuildClashMetaProfileYAML(profile)
	if err != nil {
		t.Fatalf("clash gen error: %v", err)
	}
	if strings.Contains(string(clashYamlBytes), privKey) {
		t.Errorf("private key leaked in Clash config")
	}

	// 2. Sing-box
	sbMap, err := BuildSingboxProfileJSON(profile)
	if err != nil {
		t.Fatalf("singbox gen error: %v", err)
	}
	sbBytes, _ := json.Marshal(sbMap)
	if strings.Contains(string(sbBytes), privKey) {
		t.Errorf("private key leaked in Singbox config")
	}

	// 3. Xray
	xrayMap, err := BuildXrayClientConfig(profile)
	if err != nil {
		t.Fatalf("xray gen error: %v", err)
	}
	xrayBytes, _ := json.Marshal(xrayMap)
	if strings.Contains(string(xrayBytes), privKey) {
		t.Errorf("private key leaked in Xray config")
	}

	// 4. URI & Sub
	link, _ := BuildVlessShareLink(profile)
	if strings.Contains(link, privKey) {
		t.Errorf("private key leaked in share link")
	}
}

func TestAPI_SubscriptionTokenHashingAndRevocation(t *testing.T) {
	InitAuth("master-key-12345")
	handler := setupTestServer()

	// Generate secure token
	token, err := GenerateSubscriptionToken()
	if err != nil {
		t.Fatalf("GenerateSubscriptionToken failed: %v", err)
	}

	SetActiveVlessConfig(&xray.VlessConfig{
		Enabled:             true,
		Port:                60001,
		UUID:                "b831381d-6324-4d53-ad4f-8cda48b30811",
		Flow:                "xtls-rprx-vision",
		Dest:                "www.microsoft.com:443",
		ServerNames:         []string{"www.microsoft.com"},
		Fingerprint:         "chrome",
		PublicKey:           "Af0aicE9KbySwRkPTZJrI0PfgEH5g3nydVMA79RGBCg",
		ShortIds:            []string{"0123456789abcdef"},
		OutboundOnlyPort443: true,
	})

	// Access with subscription token
	req, _ := http.NewRequest("GET", "/api/v1/export/sub?token="+token, nil)
	req.RemoteAddr = "192.0.2.15:12345"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK with valid subscription token, got %d: %s", rr.Code, rr.Body.String())
	}

	// Revoke subscription token
	RevokeSubscriptionToken(token)

	// Access again -> should be 403 Forbidden
	req, _ = http.NewRequest("GET", "/api/v1/export/sub?token="+token, nil)
	req.RemoteAddr = "192.0.2.15:12345"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden after token revocation, got %d", rr.Code)
	}
}

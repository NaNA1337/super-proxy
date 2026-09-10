package agentapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		Enabled:     true,
		Port:        443,
		UUID:        "b831381d-6324-4d53-ad4f-8cda48b30811",
		Flow:        "xtls-rprx-vision",
		Dest:        "www.microsoft.com:443",
		ServerNames: []string{"www.microsoft.com"},
		Fingerprint: "chrome",
		PublicKey:   "Af0aicE9KbySwRkPTZJrI0PfgEH5g3nydVMA79RGBCg",
		ShortIds:    []string{"0123456789abcdef"},
		OnlyPort443: true,
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
		Enabled:     true,
		Port:        443,
		UUID:        "b831381d-6324-4d53-ad4f-8cda48b30811",
		Flow:        "xtls-rprx-vision",
		Dest:        "www.microsoft.com:443",
		ServerNames: []string{"www.microsoft.com"},
		Fingerprint: "chrome",
		PublicKey:   "Af0aicE9KbySwRkPTZJrI0PfgEH5g3nydVMA79RGBCg",
		ShortIds:    []string{"0123456789abcdef"},
		OnlyPort443: true,
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
}

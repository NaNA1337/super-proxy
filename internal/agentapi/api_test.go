package agentapi

import (
	"bytes"
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



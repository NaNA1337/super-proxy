package agentapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NaNA1337/super-proxy/internal/config"
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


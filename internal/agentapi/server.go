package agentapi

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/NaNA1337/super-proxy/internal/scheduler"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// StartServer initializes and starts the Agent API Control Plane bound to localhost by default.
func StartServer(port int, schedulerInstance *scheduler.Scheduler, configKey string) *http.Server {
	return StartServerWithAddr("127.0.0.1", port, schedulerInstance, configKey)
}

// StartServerWithAddr initializes and starts the Agent API Control Plane on a specific address.
func StartServerWithAddr(listenAddr string, port int, schedulerInstance *scheduler.Scheduler, configKey string) *http.Server {
	if listenAddr == "" {
		listenAddr = "127.0.0.1"
	}
	if port <= 0 {
		port = 60000
	}

	if listenAddr == "0.0.0.0" || listenAddr == "::" {
		if configKey == "" {
			log.Fatalf("[AgentAPI] FATAL: Binding to public address %s without an API authentication key is strictly prohibited!", listenAddr)
		}
		log.Printf("[AgentAPI] WARNING: Binding to PUBLIC address %s:%d! Enforcing mandatory TLS, Bearer token authentication, and IP rate limiting.", listenAddr, port)
	}

	handler := NewHandler(schedulerInstance, configKey)
	addr := fmt.Sprintf("%s:%d", listenAddr, port)

	// Generate in-memory self-signed TLS cert
	tlsCert, err := LoadOrGenerateCert("configs/cert.pem", "configs/key.pem")
	if err != nil {
		log.Fatalf("[AgentAPI] Failed to generate TLS certificate: %v", err)
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
	}

	go func() {
		log.Printf("[AgentAPI] Server listening securely on %s", addr)
		if err := server.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[AgentAPI] Failed to start server: %v", err)
		}
	}()

	return server
}

// NewHandler constructs and returns the fully configured HTTP handler for the Agent API.
func NewHandler(schedulerInstance *scheduler.Scheduler, configKey string) http.Handler {
	SetScheduler(schedulerInstance)
	InitAuth(configKey)

	mux := http.NewServeMux()

	panicRecoveryMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("[AgentAPI] CRITICAL PANIC RECOVERED: %v", rec)
					http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				}
			}()
			// 1MB request body limit
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			next.ServeHTTP(w, r)
		})
	}

	// Middleware chain: Panic Recovery (outermost) -> Rate Limit -> Auth (innermost)
	secureChain := func(h http.Handler) http.Handler {
		return panicRecoveryMiddleware(rateLimitMiddleware(authMiddleware(h)))
	}

	mux.Handle("/api/v1/status", secureChain(http.HandlerFunc(handleStatus)))
	mux.Handle("/api/v1/system", secureChain(http.HandlerFunc(handleSystem)))
	mux.Handle("/api/v1/current-exits", secureChain(http.HandlerFunc(handleCurrentExits)))
	mux.Handle("/api/v1/slots", secureChain(http.HandlerFunc(handleSlots)))
	mux.Handle("/api/v1/pool", secureChain(http.HandlerFunc(handlePool)))
	mux.Handle("/api/v1/pool/qualified", secureChain(http.HandlerFunc(handlePoolQualified)))
	mux.Handle("/api/v1/nodes", secureChain(http.HandlerFunc(handleNodesList)))
	mux.Handle("/api/v1/routing", secureChain(http.HandlerFunc(handleRoutingOverview)))
	mux.Handle("/api/v1/client-config", secureChain(http.HandlerFunc(handleClientConfig)))
	mux.Handle("/api/v1/export/clash", secureChain(http.HandlerFunc(handleExportClash)))
	mux.Handle("/api/v1/export/singbox", secureChain(http.HandlerFunc(handleExportSingbox)))
	mux.Handle("/api/v1/export/xray", secureChain(http.HandlerFunc(handleExportXray)))
	mux.Handle("/api/v1/export/sub", secureChain(http.HandlerFunc(handleExportSub)))
	mux.Handle("/api/v1/nodes/", secureChain(http.HandlerFunc(handleNodeDetails)))
	mux.Handle("/api/v1/operations/", secureChain(http.HandlerFunc(handleOperationStatus)))
	mux.Handle("/api/v1/slots/", secureChain(http.HandlerFunc(handleSlotAction)))

	// Metrics must be authenticated
	mux.Handle("/metrics", secureChain(promhttp.Handler()))

	return mux
}

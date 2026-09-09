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

// StartServer initializes and starts the Agent API Control Plane
func StartServer(port int, schedulerInstance *scheduler.Scheduler) *http.Server {
	SetScheduler(schedulerInstance)
	InitAuth()

	mux := http.NewServeMux()

	// Middleware chain: Rate Limit FIRST (outer), then Authentication (inner)
	// This ensures unauthenticated brute-force attempts are rate-limited
	secureChain := func(h http.Handler) http.Handler {
		return rateLimitMiddleware(authMiddleware(h))
	}

	mux.Handle("/api/v1/status", secureChain(http.HandlerFunc(handleStatus)))
	mux.Handle("/api/v1/system", secureChain(http.HandlerFunc(handleSystem)))
	mux.Handle("/api/v1/current-exits", secureChain(http.HandlerFunc(handleCurrentExits)))
	mux.Handle("/api/v1/slots", secureChain(http.HandlerFunc(handleSlots)))
	mux.Handle("/api/v1/pool", secureChain(http.HandlerFunc(handlePool)))
	mux.Handle("/api/v1/pool/qualified", secureChain(http.HandlerFunc(handlePoolQualified)))
	mux.Handle("/api/v1/nodes/", secureChain(http.HandlerFunc(handleNodeDetails)))
	mux.Handle("/api/v1/operations/", secureChain(http.HandlerFunc(handleOperationStatus)))
	mux.Handle("/api/v1/slots/", secureChain(http.HandlerFunc(handleSlotAction)))

	// P1-11: Metrics must be authenticated
	mux.Handle("/metrics", secureChain(promhttp.Handler()))

	addr := fmt.Sprintf("0.0.0.0:%d", port)

	// Generate in-memory self-signed TLS cert
	tlsCert, err := LoadOrGenerateCert("configs/cert.pem", "configs/key.pem")
	if err != nil {
		log.Fatalf("[AgentAPI] Failed to generate TLS certificate: %v", err)
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*tlsCert},
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

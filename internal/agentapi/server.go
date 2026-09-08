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

// StartServer initializes the API server on the specified port with the provided scheduler instance
func StartServer(port int, s *scheduler.Scheduler) {
	SetScheduler(s)
	InitAuth()

	mux := http.NewServeMux()

	// 1. Prometheus Metrics (Anonymous but rate limited)
	mux.Handle("/metrics", rateLimitMiddleware(promhttp.Handler()))

	// 2. Read-Only Endpoints (Authenticated)
	mux.Handle("/api/v1/status", rateLimitMiddleware(authMiddleware(http.HandlerFunc(handleStatus))))
	mux.Handle("/api/v1/system", rateLimitMiddleware(authMiddleware(http.HandlerFunc(handleSystem))))
	mux.Handle("/api/v1/current-exits", rateLimitMiddleware(authMiddleware(http.HandlerFunc(handleCurrentExits))))
	mux.Handle("/api/v1/slots", rateLimitMiddleware(authMiddleware(http.HandlerFunc(handleSlots))))
	mux.Handle("/api/v1/pool", rateLimitMiddleware(authMiddleware(http.HandlerFunc(handlePool))))
	mux.Handle("/api/v1/pool/qualified", rateLimitMiddleware(authMiddleware(http.HandlerFunc(handlePoolQualified))))
	mux.Handle("/api/v1/nodes/", rateLimitMiddleware(authMiddleware(http.HandlerFunc(handleNodeDetails))))
	mux.Handle("/api/v1/operations/", rateLimitMiddleware(authMiddleware(http.HandlerFunc(handleOperationStatus))))

	// 3. Write-Only Endpoints (Authenticated)
	mux.Handle("/api/v1/slots/", rateLimitMiddleware(authMiddleware(http.HandlerFunc(handleSlotAction))))

	addr := fmt.Sprintf("0.0.0.0:%d", port)
	
	// Generate in-memory self-signed TLS cert
	tlsCert, err := GenerateSelfSignedCert()
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

	log.Printf("[AgentAPI] Server listening on https://%s", addr)
	
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("[AgentAPI] Server failed: %v", err)
	}
}

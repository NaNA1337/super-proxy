package api

import (
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func StartServer(port int) {
	mux := http.NewServeMux()

	// Metrics endpoint
	mux.Handle("/metrics", promhttp.Handler())

	// Basic API endpoints (stubbed for now)
	mux.HandleFunc("/api/nodes", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok", "nodes_tracked": true}`))
	})

	mux.HandleFunc("/api/slots", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok", "slots_active": 3}`))
	})

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	log.Printf("[API] Server listening on %s", addr)
	
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("[API] Server failed: %v", err)
	}
}

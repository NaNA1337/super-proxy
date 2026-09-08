package agentapi

import (
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"strings"
)

var (
	masterAPIKey = ""
)

func InitAuth() {
	key := os.Getenv("XRAY_MANAGER_API_KEY")
	if key == "" {
		// Log warning but allow it to be injected later via config, 
		// for now we set a strong fallback or fail secure.
		log.Println("[AgentAPI] WARNING: XRAY_MANAGER_API_KEY environment variable not set. API will reject all authenticated requests.")
	}
	masterAPIKey = key
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Printf("[AgentAPI] 401 Unauthorized (Missing Header) - IP: %s, URI: %s", r.RemoteAddr, r.RequestURI)
			http.Error(w, "Unauthorized - Missing Bearer Token", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			log.Printf("[AgentAPI] 401 Unauthorized (Malformed Header) - IP: %s, URI: %s", r.RemoteAddr, r.RequestURI)
			http.Error(w, "Unauthorized - Malformed Bearer Token", http.StatusUnauthorized)
			return
		}

		token := parts[1]
		
		// Constant time comparison to prevent timing attacks
		if masterAPIKey == "" || subtle.ConstantTimeCompare([]byte(token), []byte(masterAPIKey)) != 1 {
			log.Printf("[AgentAPI] 403 Forbidden (Invalid Token) - IP: %s, URI: %s", r.RemoteAddr, r.RequestURI)
			http.Error(w, "Forbidden - Invalid Token", http.StatusForbidden)
			return
		}

		// Log high privilege operations (Write operations)
		if r.Method != http.MethodGet {
			log.Printf("[AgentAPI-Audit] Authenticated %s request from %s to %s", r.Method, r.RemoteAddr, r.RequestURI)
		}

		next.ServeHTTP(w, r)
	})
}

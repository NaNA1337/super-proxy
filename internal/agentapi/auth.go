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

func InitAuth(configKey string) {
	key := os.Getenv("XRAY_MANAGER_API_KEY")
	if key == "" {
		key = configKey
	}
	if key == "" {
		log.Println("[AgentAPI] WARNING: Neither XRAY_MANAGER_API_KEY nor config api_key is set. API will reject all authenticated requests.")
	} else {
		log.Println("[AgentAPI] Authentication initialized successfully.")
	}
	masterAPIKey = key
}

// SetMasterAPIKey dynamically sets the API key (for testing and runtime config reload)
func SetMasterAPIKey(key string) {
	masterAPIKey = key
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
				token = parts[1]
			} else {
				log.Printf("[AgentAPI] 401 Unauthorized (Malformed Header) - IP: %s, URI: %s", r.RemoteAddr, r.RequestURI)
				http.Error(w, "Unauthorized - Malformed Bearer Token", http.StatusUnauthorized)
				return
			}
		} else {
			// Allow query parameter token for subscription export URLs (Clash/Sing-box/v2rayN)
			if qToken := r.URL.Query().Get("token"); qToken != "" {
				token = qToken
			} else if qKey := r.URL.Query().Get("key"); qKey != "" {
				token = qKey
			}
		}

		if token == "" {
			log.Printf("[AgentAPI] 401 Unauthorized (Missing Header) - IP: %s, URI: %s", r.RemoteAddr, r.RequestURI)
			http.Error(w, "Unauthorized - Missing Bearer Token", http.StatusUnauthorized)
			return
		}

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

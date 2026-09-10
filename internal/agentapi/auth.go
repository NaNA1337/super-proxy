package agentapi

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

var (
	masterAPIKey          = ""
	subTokensMu           sync.RWMutex
	subTokenHashes        = make(map[[32]byte]bool)
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

// GenerateSubscriptionToken generates a cryptographically secure random 32-byte hex token.
func GenerateSubscriptionToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate secure token: %w", err)
	}
	token := "sub_" + hex.EncodeToString(b)
	RegisterSubscriptionToken(token)
	return token, nil
}

// RegisterSubscriptionToken records a subscription token by storing only its SHA-256 hash.
func RegisterSubscriptionToken(token string) {
	if token == "" {
		return
	}
	hash := sha256.Sum256([]byte(token))
	subTokensMu.Lock()
	defer subTokensMu.Unlock()
	subTokenHashes[hash] = true
}

// RevokeSubscriptionToken removes a subscription token hash so it can no longer be used.
func RevokeSubscriptionToken(token string) {
	if token == "" {
		return
	}
	hash := sha256.Sum256([]byte(token))
	subTokensMu.Lock()
	defer subTokensMu.Unlock()
	delete(subTokenHashes, hash)
}

// ValidateToken checks whether the provided token matches the master API key or a registered subscription token.
func ValidateToken(token string) bool {
	if token == "" {
		return false
	}
	// Check master API key
	if masterAPIKey != "" && subtle.ConstantTimeCompare([]byte(token), []byte(masterAPIKey)) == 1 {
		return true
	}
	// Check hashed subscription tokens
	hash := sha256.Sum256([]byte(token))
	subTokensMu.RLock()
	defer subTokensMu.RUnlock()
	return subTokenHashes[hash]
}

// sanitizeURI masks query parameters containing tokens or keys to prevent secret leakage in logs.
func sanitizeURI(uri string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	q := u.Query()
	modified := false
	if q.Has("token") {
		q.Set("token", "[REDACTED]")
		modified = true
	}
	if q.Has("key") {
		q.Set("key", "[REDACTED]")
	}
	if modified {
		u.RawQuery = q.Encode()
	}
	return u.String()
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
				log.Printf("[AgentAPI] 401 Unauthorized (Malformed Header) - IP: %s, URI: %s", r.RemoteAddr, sanitizeURI(r.RequestURI))
				http.Error(w, "Unauthorized - Malformed Bearer Token", http.StatusUnauthorized)
				return
			}
		} else {
			// Allow query parameter token for subscription export URLs
			if qToken := r.URL.Query().Get("token"); qToken != "" {
				token = qToken
			} else if qKey := r.URL.Query().Get("key"); qKey != "" {
				token = qKey
			}
		}

		if token == "" {
			log.Printf("[AgentAPI] 401 Unauthorized (Missing Header) - IP: %s, URI: %s", r.RemoteAddr, sanitizeURI(r.RequestURI))
			http.Error(w, "Unauthorized - Missing Token", http.StatusUnauthorized)
			return
		}

		if !ValidateToken(token) {
			log.Printf("[AgentAPI] 403 Forbidden (Invalid Token) - IP: %s, URI: %s", r.RemoteAddr, sanitizeURI(r.RequestURI))
			http.Error(w, "Forbidden - Invalid Token", http.StatusForbidden)
			return
		}

		// Log high privilege operations (Write operations)
		if r.Method != http.MethodGet {
			log.Printf("[AgentAPI-Audit] Authenticated %s request from %s to %s", r.Method, r.RemoteAddr, sanitizeURI(r.RequestURI))
		}

		next.ServeHTTP(w, r)
	})
}

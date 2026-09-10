package agentapi

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ClientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

var (
	rlMu sync.Mutex
	// Key is IP address string
	visitors = make(map[string]*ClientLimiter)

	// Unauthenticated config: 5 req/sec, burst of 10
	unauthLimit = rate.Limit(5)
	unauthBurst = 10

	// Authenticated config: 50 req/sec, burst of 100
	authLimit = rate.Limit(50)
	authBurst = 100
)

func init() {
	go cleanupVisitors()
}

// isRequestAuthenticated performs a check if the request provides a valid master API key or subscription token.
// Used by the rate limiter (which runs before auth middleware) to determine the rate bucket.
func isRequestAuthenticated(r *http.Request) bool {
	if r == nil {
		return false
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			if ValidateToken(parts[1]) {
				return true
			}
		}
	}
	if qToken := r.URL.Query().Get("token"); qToken != "" {
		if ValidateToken(qToken) {
			return true
		}
	}
	if qKey := r.URL.Query().Get("key"); qKey != "" {
		if ValidateToken(qKey) {
			return true
		}
	}
	return false
}

func getVisitorLimiter(ip string, isAuthenticated bool) *rate.Limiter {
	rlMu.Lock()
	defer rlMu.Unlock()

	v, exists := visitors[ip]
	if !exists {
		l := rate.NewLimiter(unauthLimit, unauthBurst)
		if isAuthenticated {
			l = rate.NewLimiter(authLimit, authBurst)
		}
		visitors[ip] = &ClientLimiter{limiter: l, lastSeen: time.Now()}
		return l
	}

	// Update limiter dynamically based on auth status
	if isAuthenticated && v.limiter.Limit() == unauthLimit {
		v.limiter.SetLimit(authLimit)
		v.limiter.SetBurst(authBurst)
	} else if !isAuthenticated && v.limiter.Limit() == authLimit {
		v.limiter.SetLimit(unauthLimit)
		v.limiter.SetBurst(unauthBurst)
	}

	v.lastSeen = time.Now()
	return v.limiter
}

func cleanupVisitors() {
	for {
		time.Sleep(1 * time.Minute)
		rlMu.Lock()
		for ip, v := range visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(visitors, ip)
			}
		}
		rlMu.Unlock()
	}
}

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			ip = host
		} else if ip == "" {
			ip = "127.0.0.1"
		}

		// Actually validate the token to determine the correct rate bucket
		// (not just check for header presence, which can be spoofed)
		isAuthenticated := isRequestAuthenticated(r)

		limiter := getVisitorLimiter(ip, isAuthenticated)
		if !limiter.Allow() {
			log.Printf("[AgentAPI] 429 Too Many Requests - IP: %s, Authenticated: %v", ip, isAuthenticated)
			http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

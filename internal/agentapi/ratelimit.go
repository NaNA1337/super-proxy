package agentapi

import (
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ClientLimiter struct {
	limiter *rate.Limiter
	lastSeen time.Time
}

var (
	mu sync.Mutex
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

func getVisitorLimiter(ip string, isAuthenticated bool) *rate.Limiter {
	mu.Lock()
	defer mu.Unlock()

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
		mu.Lock()
		for ip, v := range visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(visitors, ip)
			}
		}
		mu.Unlock()
	}
}

func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			log.Printf("[AgentAPI] RateLimit warning: failed to parse remote addr %s", r.RemoteAddr)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		// Auth status is populated in Context by AuthMiddleware if it runs first.
		// Alternatively, we check it here loosely just to decide the bucket.
		// Note: true authentication enforcement happens in AuthMiddleware.
		authHeader := r.Header.Get("Authorization")
		isAuthenticatedAttempt := authHeader != ""

		limiter := getVisitorLimiter(ip, isAuthenticatedAttempt)
		if !limiter.Allow() {
			http.Error(w, "429 Too Many Requests", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

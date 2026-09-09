package reputation

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

type EngineConfig struct {
	FailurePolicy string        // "conservative" (default) or "lenient"
	CacheTTL      time.Duration // default 24h
}

type Engine struct {
	providers     []Provider
	cache         *Cache
	failurePolicy string
	mu            sync.RWMutex
}

func NewEngine() *Engine {
	return NewEngineWithConfig(EngineConfig{
		FailurePolicy: "conservative",
		CacheTTL:      24 * time.Hour,
	})
}

func NewEngineWithConfig(cfg EngineConfig) *Engine {
	if cfg.FailurePolicy == "" {
		cfg.FailurePolicy = "conservative"
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 24 * time.Hour
	}
	return &Engine{
		providers:     []Provider{},
		cache:         NewCache(cfg.CacheTTL),
		failurePolicy: cfg.FailurePolicy,
	}
}

// AddProvider registers a new reputation provider.
func (e *Engine) AddProvider(p Provider) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.providers = append(e.providers, p)
}

// FailurePolicy returns the configured reputation failure policy ("conservative" or "lenient").
func (e *Engine) FailurePolicy() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.failurePolicy
}

// GetCache returns the internal TTL cache.
func (e *Engine) GetCache() *Cache {
	return e.cache
}

// EvaluateIP runs the IP against cache and all registered providers in parallel.
func (e *Engine) EvaluateIP(ctx context.Context, ip string) (*Result, error) {
	// 1. Check TTL cache first
	if cached, hit := e.cache.Get(ip); hit {
		log.Printf("[Reputation] Cache HIT for %s: Status=%s, Penalty=%d, HardReject=%v",
			ip, cached.Status, cached.ScorePenalty, cached.HardReject)
		return cached, nil
	}

	e.mu.RLock()
	providers := make([]Provider, len(e.providers))
	copy(providers, e.providers)
	e.mu.RUnlock()

	if len(providers) == 0 {
		unknownRes := &Result{
			IP:             ip,
			Status:         StatusUnknown,
			ProviderReason: "UNKNOWN (No reputation providers configured)",
		}
		return unknownRes, nil
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	finalResult := &Result{
		IP:     ip,
		Status: StatusGood, // default if all succeed cleanly; changed if penalties or unknown
	}
	var errMessages []string
	unknownCount := 0
	successCount := 0

	for _, p := range providers {
		wg.Add(1)
		go func(provider Provider) {
			defer wg.Done()

			// Timeout individual provider query if needed
			provCtx, provCancel := context.WithTimeout(ctx, 8*time.Second)
			defer provCancel()

			res, err := provider.CheckIP(provCtx, ip)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				errMessages = append(errMessages, fmt.Sprintf("%s: %v", provider.Name(), err))
				unknownCount++
				return
			}

			successCount++

			// Track Network Intelligence
			if res.NetworkInfo.ASN != "" {
				finalResult.NetworkInfo.ASN = res.NetworkInfo.ASN
			}
			if res.NetworkInfo.ISP != "" {
				finalResult.NetworkInfo.ISP = res.NetworkInfo.ISP
			}
			if res.NetworkInfo.Organization != "" {
				finalResult.NetworkInfo.Organization = res.NetworkInfo.Organization
			}
			if res.NetworkInfo.NetworkType != "" {
				finalResult.NetworkInfo.NetworkType = res.NetworkInfo.NetworkType
			}
			if res.NetworkInfo.IsVPN {
				finalResult.NetworkInfo.IsVPN = true
			}
			if res.NetworkInfo.IsProxy {
				finalResult.NetworkInfo.IsProxy = true
			}
			if res.NetworkInfo.IsTor {
				finalResult.NetworkInfo.IsTor = true
			}
			if res.NetworkInfo.IsHosting {
				finalResult.NetworkInfo.IsHosting = true
			}

			// Handle Status & Penalties
			if res.Status == StatusUnknown {
				unknownCount++
				finalResult.ProviderReason += fmt.Sprintf("[%s: UNKNOWN - %s] ", provider.Name(), res.ProviderReason)
			} else if res.HardReject {
				finalResult.Status = StatusBad
				finalResult.HardReject = true
				finalResult.ProviderReason += fmt.Sprintf("[%s: HARD REJECT - %s] ", provider.Name(), res.ProviderReason)
			} else if res.ScorePenalty > 0 {
				finalResult.Status = StatusBad
				finalResult.ScorePenalty += res.ScorePenalty
				finalResult.ProviderReason += fmt.Sprintf("[%s: PENALTY (-%d) - %s] ", provider.Name(), res.ScorePenalty, res.ProviderReason)
			} else {
				finalResult.ProviderReason += fmt.Sprintf("[%s: %s] ", provider.Name(), res.ProviderReason)
			}
		}(p)
	}

	wg.Wait()

	// If all providers failed or timed out:
	if successCount == 0 {
		finalResult.Status = StatusUnknown
		finalResult.ProviderReason = fmt.Sprintf("UNKNOWN: all providers failed (%v)", errMessages)
		log.Printf("[Reputation] IP %s reputation check UNKNOWN: %s", ip, finalResult.ProviderReason)
		// Cache unknown results for short duration or don't cache to allow retry
		return finalResult, nil
	}

	// If any provider returned unknown and failure policy is conservative, mark UNKNOWN unless hard rejected
	if unknownCount > 0 && !finalResult.HardReject && e.failurePolicy == "conservative" {
		finalResult.Status = StatusUnknown
	}

	// Cache the result
	e.cache.Set(ip, finalResult)

	return finalResult, nil
}

package reputation

import (
	"sync"
	"sync/atomic"
	"time"
)

type cacheEntry struct {
	result    *Result
	expiresAt time.Time
}

type providerCacheEntry struct {
	result    *ReputationResult
	expiresAt time.Time
}

// Cache provides an in-memory concurrent TTL cache for reputation lookups,
// supporting both overall aggregated evaluations and per-provider results with provider-specific TTLs.
type Cache struct {
	mu              sync.RWMutex
	entries         map[string]cacheEntry
	providerEntries map[string]map[string]providerCacheEntry
	ttl             time.Duration
	providerTTLs    map[string]time.Duration
	hits            atomic.Int64
	misses          atomic.Int64
	requests        atomic.Int64
}

// NewCache creates a new reputation cache with the given aggregate TTL and default provider TTLs.
func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		entries:         make(map[string]cacheEntry),
		providerEntries: make(map[string]map[string]providerCacheEntry),
		ttl:             ttl,
		providerTTLs: map[string]time.Duration{
			"AbuseIPDB": 24 * time.Hour,
			"GreyNoise": 24 * time.Hour,
			"IPQS":      24 * time.Hour,
			"IPInfo":    7 * 24 * time.Hour,
		},
	}
}

// SetProviderTTL customizes the TTL for a specific provider.
func (c *Cache) SetProviderTTL(provider string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.providerTTLs[provider] = ttl
}

// GetProvider retrieves a cached provider evaluation if still valid.
func (c *Cache) GetProvider(ip, provider string) (*ReputationResult, bool) {
	c.requests.Add(1)
	c.mu.RLock()
	providers, ok := c.providerEntries[ip]
	if !ok {
		c.mu.RUnlock()
		c.misses.Add(1)
		return nil, false
	}
	entry, exists := providers[provider]
	c.mu.RUnlock()

	if !exists || time.Now().After(entry.expiresAt) {
		c.misses.Add(1)
		return nil, false
	}

	c.hits.Add(1)
	return entry.result, true
}

// SetProvider stores a provider's reputation evaluation with provider-specific TTL.
func (c *Cache) SetProvider(ip, provider string, res *ReputationResult) {
	c.SetProviderUntil(ip, provider, res, time.Now().Add(c.ProviderTTL(provider)))
}

// ProviderTTL returns the configured freshness window for a provider.
func (c *Cache) ProviderTTL(provider string) time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if ttl, ok := c.providerTTLs[provider]; ok && ttl > 0 {
		return ttl
	}
	return c.ttl
}

// TTL returns the aggregate freshness window.
func (c *Cache) TTL() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ttl
}

// SetProviderUntil stores a provider result without extending its original
// expiry. This is used when hydrating the in-memory cache from durable evidence.
func (c *Cache) SetProviderUntil(ip, provider string, res *ReputationResult, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.providerEntries[ip]; !ok {
		c.providerEntries[ip] = make(map[string]providerCacheEntry)
	}
	c.providerEntries[ip][provider] = providerCacheEntry{
		result:    res,
		expiresAt: expiresAt,
	}
}

// Get retrieves a cached aggregated reputation result if not expired.
func (c *Cache) Get(ip string) (*Result, bool) {
	c.requests.Add(1)
	c.mu.RLock()
	entry, exists := c.entries[ip]
	c.mu.RUnlock()

	if !exists || time.Now().After(entry.expiresAt) {
		c.misses.Add(1)
		return nil, false
	}

	c.hits.Add(1)
	return entry.result, true
}

// Set stores an aggregated reputation result in the cache with the configured TTL.
func (c *Cache) Set(ip string, res *Result) {
	c.SetUntil(ip, res, time.Now().Add(c.ttl))
}

// SetUntil stores an aggregate result with an explicit expiry.
func (c *Cache) SetUntil(ip string, res *Result, expiresAt time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[ip] = cacheEntry{
		result:    res,
		expiresAt: expiresAt,
	}
}

// Stats returns the cache hits, misses, and total requests.
func (c *Cache) Stats() (hits, misses, requests int64) {
	return c.hits.Load(), c.misses.Load(), c.requests.Load()
}

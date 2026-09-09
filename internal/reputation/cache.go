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

// Cache provides an in-memory concurrent TTL cache for reputation lookups.
type Cache struct {
	mu       sync.RWMutex
	entries  map[string]cacheEntry
	ttl      time.Duration
	hits     atomic.Int64
	misses   atomic.Int64
	requests atomic.Int64
}

// NewCache creates a new reputation cache with the given TTL.
func NewCache(ttl time.Duration) *Cache {
	return &Cache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
	}
}

// Get retrieves a cached reputation result if not expired.
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

// Set stores a reputation result in the cache with the configured TTL.
func (c *Cache) Set(ip string, res *Result) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[ip] = cacheEntry{
		result:    res,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Stats returns the cache hits, misses, and total requests.
func (c *Cache) Stats() (hits, misses, requests int64) {
	return c.hits.Load(), c.misses.Load(), c.requests.Load()
}

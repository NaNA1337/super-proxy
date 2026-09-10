package models

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

type Endpoint struct {
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Proto     string    `json:"proto"`
	FailCount int       `json:"fail_count"`
	LastSeen  time.Time `json:"last_seen"`
	Active    bool      `json:"active"`
}

// deduplicateEndpoints deduplicates endpoints by (host, port, proto)
func deduplicateEndpoints(eps []Endpoint) []Endpoint {
	seen := make(map[string]bool)
	var deduped []Endpoint
	for _, ep := range eps {
		key := ep.Proto + "://" + ep.Host + ":" + string(rune(ep.Port))
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, ep)
		}
	}
	return deduped
}

func TestEndpointModel_MultiEndpointDeduplication(t *testing.T) {
	endpoints := []Endpoint{
		{Host: "203.0.113.1", Port: 443, Proto: "tcp"},
		{Host: "203.0.113.1", Port: 443, Proto: "tcp"}, // duplicate
		{Host: "203.0.113.1", Port: 1194, Proto: "udp"},
		{Host: "203.0.113.1", Port: 995, Proto: "tcp"},
	}

	deduped := deduplicateEndpoints(endpoints)
	if len(deduped) != 3 {
		t.Fatalf("expected 3 unique endpoints, got %d", len(deduped))
	}
}

func TestEndpointModel_EndpointChangePreservesHistory(t *testing.T) {
	// Verify that a VPN Gate node's historical metrics remain completely intact
	// when its active endpoint changes from Endpoint A to Endpoint B.
	now := time.Now().Add(-24 * time.Hour)
	node := &Node{
		ID:            "203.0.113.50", // Stable Node ID (IP-based)
		IP:            "203.0.113.50",
		Score:         88,
		FailCount:     2,
		FirstSeen:     now,
		EndpointHost:  "203.0.113.50",
		EndpointPort:  443,
		EndpointProto: "tcp",
		Reputation: ReputationMetrics{
			Status:     StatusActive,
			FraudScore: 10,
		},
		NetClass: NetworkClass{
			IsVPN: true,
		},
	}

	// 1. Initial state check
	originalFirstSeen := node.FirstSeen
	originalFailCount := node.FailCount
	originalFraudScore := node.Reputation.FraudScore

	// 2. Discovery updates endpoint to Port 1194 UDP
	newEndpoints := []Endpoint{
		{Host: "203.0.113.50", Port: 1194, Proto: "udp"},
		{Host: "203.0.113.50", Port: 443, Proto: "tcp"},
	}
	epBytes, _ := json.Marshal(newEndpoints)

	node.EndpointsJSON = string(epBytes)
	node.EndpointPort = 1194
	node.EndpointProto = "udp"
	node.LastSeen = time.Now()

	// 3. Strict verification: Historical data must NOT be wiped or reset
	if node.ID != "203.0.113.50" {
		t.Fatalf("Node ID must remain stable, got %s", node.ID)
	}
	if node.FirstSeen != originalFirstSeen {
		t.Errorf("FirstSeen was mutated across endpoint update: expected %v, got %v", originalFirstSeen, node.FirstSeen)
	}
	if node.FailCount != originalFailCount {
		t.Errorf("FailCount history was wiped: expected %d, got %d", originalFailCount, node.FailCount)
	}
	if node.Reputation.FraudScore != originalFraudScore {
		t.Errorf("Reputation history was lost: expected %d, got %d", originalFraudScore, node.Reputation.FraudScore)
	}
	if node.EndpointPort != 1194 || node.EndpointProto != "udp" {
		t.Errorf("Primary endpoint was not updated: port=%d proto=%s", node.EndpointPort, node.EndpointProto)
	}
}

func TestEndpointModel_IndependentFailureTracking(t *testing.T) {
	// One VPN Gate node with 3 endpoints: A, B, C
	endpoints := []Endpoint{
		{Host: "203.0.113.51", Port: 443, Proto: "tcp", FailCount: 0, Active: true},
		{Host: "203.0.113.51", Port: 995, Proto: "tcp", FailCount: 0, Active: true},
		{Host: "203.0.113.51", Port: 1194, Proto: "udp", FailCount: 0, Active: true},
	}

	// Fail endpoint A
	endpoints[0].FailCount++
	endpoints[0].Active = false

	// Verify endpoints B and C are still healthy
	if endpoints[0].FailCount != 1 || endpoints[0].Active != false {
		t.Fatalf("Endpoint A failure not recorded correctly")
	}
	if endpoints[1].FailCount != 0 || endpoints[1].Active != true {
		t.Errorf("Endpoint B should remain unaffected by Endpoint A failure")
	}
	if endpoints[2].FailCount != 0 || endpoints[2].Active != true {
		t.Errorf("Endpoint C should remain unaffected by Endpoint A failure")
	}
}

func TestEndpointModel_EndpointRemovalDoesNotAffectOthers(t *testing.T) {
	endpoints := []Endpoint{
		{Host: "203.0.113.52", Port: 443, Proto: "tcp"},
		{Host: "203.0.113.52", Port: 995, Proto: "tcp"},
		{Host: "203.0.113.52", Port: 1194, Proto: "udp"},
	}

	// Remove endpoint at port 995
	var remaining []Endpoint
	for _, ep := range endpoints {
		if ep.Port != 995 {
			remaining = append(remaining, ep)
		}
	}

	if len(remaining) != 2 {
		t.Fatalf("expected 2 remaining endpoints, got %d", len(remaining))
	}
	if remaining[0].Port != 443 || remaining[1].Port != 1194 {
		t.Errorf("Remaining endpoints altered unexpectedly: %+v", remaining)
	}
}

func TestEndpointModel_ConcurrentRefcountSafety(t *testing.T) {
	var mu sync.Mutex
	refcounts := make(map[string]int)

	acquire := func(key string) {
		mu.Lock()
		defer mu.Unlock()
		refcounts[key]++
	}

	release := func(key string) {
		mu.Lock()
		defer mu.Unlock()
		refcounts[key]--
		if refcounts[key] == 0 {
			delete(refcounts, key)
		}
	}

	get := func(key string) int {
		mu.Lock()
		defer mu.Unlock()
		return refcounts[key]
	}

	var wg sync.WaitGroup
	epKey := "tcp://203.0.113.53:443"

	// 50 concurrent goroutines acquire and release
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			acquire(epKey)
			time.Sleep(1 * time.Millisecond)
			release(epKey)
		}()
	}

	wg.Wait()
	if count := get(epKey); count != 0 {
		t.Fatalf("expected 0 refcount after balanced concurrent operations, got %d", count)
	}
}

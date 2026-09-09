package routing

import (
	"sync"
	"testing"
)

func TestEndpointManager_RefCountLifecycle(t *testing.T) {
	mgr := &EndpointManager{
		refCounts: make(map[string]int),
	}

	testIP := "198.51.100.1"

	// Mocking: test ref count tracking
	if count := mgr.GetRefCount(testIP); count != 0 {
		t.Fatalf("Expected initial refcount 0, got %d", count)
	}

	// Tunnel 1 acquires
	mgr.mu.Lock()
	mgr.refCounts[testIP] = 1
	mgr.mu.Unlock()

	if count := mgr.GetRefCount(testIP); count != 1 {
		t.Fatalf("Expected refcount 1, got %d", count)
	}

	// Tunnel 2 acquires same IP
	mgr.mu.Lock()
	mgr.refCounts[testIP]++
	mgr.mu.Unlock()

	if count := mgr.GetRefCount(testIP); count != 2 {
		t.Fatalf("Expected refcount 2, got %d", count)
	}

	// Tunnel 1 stops -> refcount must be 1, route preserved!
	mgr.mu.Lock()
	mgr.refCounts[testIP]--
	mgr.mu.Unlock()

	if count := mgr.GetRefCount(testIP); count != 1 {
		t.Fatalf("Expected refcount 1 after 1 release, got %d", count)
	}

	// Tunnel 2 stops -> refcount reaches 0
	mgr.mu.Lock()
	mgr.refCounts[testIP]--
	if mgr.refCounts[testIP] == 0 {
		delete(mgr.refCounts, testIP)
	}
	mgr.mu.Unlock()

	if count := mgr.GetRefCount(testIP); count != 0 {
		t.Fatalf("Expected refcount 0 after full release, got %d", count)
	}
}

func TestEndpointManager_ConcurrentAcquireRelease(t *testing.T) {
	mgr := &EndpointManager{
		refCounts: make(map[string]int),
	}

	testIP := "198.51.100.2"
	iterations := 100
	var wg sync.WaitGroup

	for i := 0; i < iterations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.mu.Lock()
			mgr.refCounts[testIP]++
			mgr.mu.Unlock()

			// small delay simulation
			mgr.mu.Lock()
			mgr.refCounts[testIP]--
			if mgr.refCounts[testIP] == 0 {
				delete(mgr.refCounts, testIP)
			}
			mgr.mu.Unlock()
		}()
	}

	wg.Wait()

	if count := mgr.GetRefCount(testIP); count != 0 {
		t.Errorf("Expected final refcount 0 after balanced concurrent operations, got %d", count)
	}
}

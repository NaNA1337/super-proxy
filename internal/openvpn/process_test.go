package openvpn

import (
	"context"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
)

func createTestTunnel(ctx context.Context, cancel context.CancelFunc, name string, args ...string) (*Tunnel, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return cmd.Process.Signal(syscall.SIGTERM)
		}
		return nil
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	t := &Tunnel{
		ID:        "slot-test",
		SlotIndex: 99,
		Interface: "tun99",
		Node: &models.Node{
			IP: "192.0.2.99",
		},
		Cmd:      cmd,
		Cancel:   cancel,
		State:    "ACTIVE",
		doneChan: make(chan struct{}),
	}

	// Single waiter goroutine
	go func() {
		defer close(t.doneChan)
		err := cmd.Wait()
		t.Mu.Lock()
		t.exitErr = err
		t.State = "FAILED"
		t.Mu.Unlock()
		t.cleanup()
	}()

	return t, nil
}

func TestProcessLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tunnel, err := createTestTunnel(ctx, cancel, "sleep", "10")
	if err != nil {
		t.Fatalf("failed to create test tunnel: %v", err)
	}

	// Stop cleanly
	tunnel.Stop()

	select {
	case <-tunnel.Done():
		// Succeeded
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for tunnel to terminate")
	}

	tunnel.Mu.Lock()
	state := tunnel.State
	tunnel.Mu.Unlock()

	if state != "FAILED" {
		t.Errorf("expected state FAILED after exit, got %s", state)
	}
}

func TestStopBeforeProcessExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tunnel, err := createTestTunnel(ctx, cancel, "sleep", "30")
	if err != nil {
		t.Fatalf("failed to create test tunnel: %v", err)
	}

	// Verify running initially
	tunnel.Mu.Lock()
	initActive := tunnel.State == "ACTIVE"
	tunnel.Mu.Unlock()
	if !initActive {
		t.Fatalf("tunnel should be active initially")
	}

	// Stop while running
	start := time.Now()
	tunnel.Stop()
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Errorf("Stop took too long to terminate process: %v", elapsed)
	}

	select {
	case <-tunnel.Done():
		// Confirmed exited
	default:
		t.Fatalf("Done channel must be closed after Stop")
	}
}

func TestProcessUnexpectedExit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tunnel, err := createTestTunnel(ctx, cancel, "sleep", "2")
	if err != nil {
		t.Fatalf("failed to create test tunnel: %v", err)
	}

	// Kill child directly from outside without calling tunnel.Stop()
	if err := tunnel.Cmd.Process.Kill(); err != nil {
		t.Fatalf("failed to kill process: %v", err)
	}

	select {
	case <-tunnel.Done():
		// Waiter must detect process exit
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for waiter goroutine to detect exit")
	}

	tunnel.Mu.Lock()
	state := tunnel.State
	tunnel.Mu.Unlock()

	if state != "FAILED" {
		t.Errorf("expected state FAILED after unexpected exit, got %s", state)
	}
}

func TestStopTimeout(t *testing.T) {
	// A process that explicitly ignores SIGTERM to test timeout + SIGKILL fallback
	ctx, cancel := context.WithCancel(context.Background())
	tunnel, err := createTestTunnel(ctx, cancel, "python3", "-c", "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(20)")
	if err != nil {
		t.Fatalf("failed to start trapping process: %v", err)
	}

	// Give python process time to execute signal handler setup
	time.Sleep(300 * time.Millisecond)

	start := time.Now()
	tunnel.Stop() // will time out on SIGTERM and send SIGKILL after 5s
	elapsed := time.Since(start)

	if elapsed < 4*time.Second || elapsed > 8*time.Second {
		t.Errorf("expected Stop to wait ~5s before SIGKILL, took %v", elapsed)
	}

	select {
	case <-tunnel.Done():
		// Exited
	default:
		t.Fatalf("tunnel must be reaped after SIGKILL")
	}
}

func TestKillAfterTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	tunnel, err := createTestTunnel(ctx, cancel, "bash", "-c", "trap '' TERM; sleep 30")
	if err != nil {
		t.Fatalf("failed to start process: %v", err)
	}

	done := make(chan struct{})
	go func() {
		tunnel.Stop()
		close(done)
	}()

	select {
	case <-done:
		// Succeeded
	case <-time.After(8 * time.Second):
		t.Fatalf("timed out: tunnel.Stop() failed to kill stubborn process")
	}
}

func TestCleanupExactlyOnce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "sleep", "1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start process: %v", err)
	}

	var cleanupCount atomic.Int32
	tunnel := &Tunnel{
		ID:        "slot-cleanup-test",
		SlotIndex: 98,
		Interface: "tun98",
		Node: &models.Node{
			IP: "192.0.2.98",
		},
		Cmd:      cmd,
		Cancel:   cancel,
		State:    "ACTIVE",
		doneChan: make(chan struct{}),
	}

	// Override cleanup behavior via sync.Once
	customCleanup := func() {
		tunnel.cleanupOnce.Do(func() {
			cleanupCount.Add(1)
		})
	}

	go func() {
		defer close(tunnel.doneChan)
		_ = cmd.Wait()
		customCleanup()
	}()

	// Concurrent Stop() and natural process exit
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tunnel.Stop()
			customCleanup()
		}()
	}
	wg.Wait()

	if count := cleanupCount.Load(); count != 1 {
		t.Fatalf("cleanup was executed %d times, expected exactly 1", count)
	}
}

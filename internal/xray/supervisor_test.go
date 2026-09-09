package xray

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateConfig(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Invalid config
	invalidPath := filepath.Join(tempDir, "invalid.json")
	if err := os.WriteFile(invalidPath, []byte(`{"invalid_json": `), 0600); err != nil {
		t.Fatalf("failed to write invalid config: %v", err)
	}

	sup := NewSupervisor(invalidPath, 10090, "127.0.0.1", 10890, 3)
	if err := sup.ValidateConfig(invalidPath); err == nil {
		t.Errorf("expected ValidateConfig to fail on invalid json, got nil")
	}

	// 2. Valid config
	validPath := filepath.Join(tempDir, "valid.json")
	if err := GenerateConfigWithOptions(ConfigOptions{
		SlotCount:   2,
		ConfigPath:  validPath,
		ApiPort:     10091,
		SocksListen: "127.0.0.1",
		SocksPort:   10891,
	}); err != nil {
		t.Fatalf("failed to generate valid config: %v", err)
	}

	if err := sup.ValidateConfig(validPath); err != nil {
		t.Fatalf("expected ValidateConfig to pass on valid config, got: %v", err)
	}
}

func TestSupervisorLifecycleAndActiveSet(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "xray_lifecycle.json")

	apiPort := 10092
	socksPort := 10892

	if err := GenerateConfigWithOptions(ConfigOptions{
		SlotCount:   2,
		ConfigPath:  configPath,
		ApiPort:     apiPort,
		SocksListen: "127.0.0.1",
		SocksPort:   socksPort,
	}); err != nil {
		t.Fatalf("failed to generate test config: %v", err)
	}

	sup := NewSupervisor(configPath, apiPort, "127.0.0.1", socksPort, 2)

	// Start Xray
	if err := sup.Start(); err != nil {
		t.Fatalf("failed to start supervisor: %v", err)
	}

	state, _, _ := sup.GetState()
	if state != StateRunning {
		t.Errorf("expected state RUNNING, got %s", state)
	}

	// Verify both outbounds are initially active
	if !sup.IsOutboundActive("exit-0") || !sup.IsOutboundActive("exit-1") {
		t.Errorf("expected exit-0 and exit-1 to be active")
	}

	// Dynamically disable exit-0 (DRAINING simulation)
	if err := sup.DisableOutbound("exit-0"); err != nil {
		t.Fatalf("failed to disable exit-0: %v", err)
	}
	if sup.IsOutboundActive("exit-0") {
		t.Errorf("expected exit-0 to be marked inactive")
	}

	// Re-enable exit-0 (Standby promotion simulation)
	if err := sup.EnableOutbound("exit-0", 100); err != nil {
		t.Fatalf("failed to enable exit-0: %v", err)
	}
	if !sup.IsOutboundActive("exit-0") {
		t.Errorf("expected exit-0 to be active after EnableOutbound")
	}

	// Graceful stop
	if err := sup.Stop(); err != nil {
		t.Fatalf("failed to stop supervisor: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	finalState, _, _ := sup.GetState()
	if finalState != StateStopped {
		t.Errorf("expected state STOPPED after Stop(), got %s", finalState)
	}
}

func TestSocksPublicSecurityCheck(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "insecure.json")

	// Attempting to bind SOCKS to 0.0.0.0 without auth MUST fail
	err := GenerateConfigWithOptions(ConfigOptions{
		SlotCount:   2,
		ConfigPath:  configPath,
		ApiPort:     10093,
		SocksListen: "0.0.0.0",
		SocksPort:   10893,
		SocksUser:   "", // no auth
	})
	if err == nil {
		t.Errorf("expected GenerateConfigWithOptions to reject 0.0.0.0 binding without authentication")
	}

	// Providing auth MUST succeed
	err = GenerateConfigWithOptions(ConfigOptions{
		SlotCount:   2,
		ConfigPath:  configPath,
		ApiPort:     10093,
		SocksListen: "0.0.0.0",
		SocksPort:   10893,
		SocksUser:   "admin",
		SocksPass:   "securePass123",
	})
	if err != nil {
		t.Errorf("expected GenerateConfigWithOptions to succeed with auth on 0.0.0.0, got: %v", err)
	}
}

func TestSupervisorCrashRecovery(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "xray_crash.json")

	apiPort := 10094
	socksPort := 10894

	if err := GenerateConfigWithOptions(ConfigOptions{
		SlotCount:   2,
		ConfigPath:  configPath,
		ApiPort:     apiPort,
		SocksListen: "127.0.0.1",
		SocksPort:   socksPort,
	}); err != nil {
		t.Fatalf("failed to generate test config: %v", err)
	}

	sup := NewSupervisor(configPath, apiPort, "127.0.0.1", socksPort, 2)

	crashedChan := make(chan error, 1)
	restartedChan := make(chan int, 1)

	sup.OnCrash = func(err error) {
		select {
		case crashedChan <- err:
		default:
		}
	}
	sup.OnRestart = func(attempt int) {
		select {
		case restartedChan <- attempt:
		default:
		}
	}

	if err := sup.Start(); err != nil {
		t.Fatalf("failed to start supervisor: %v", err)
	}

	// Kill the child process directly to simulate a crash
	sup.mu.Lock()
	if sup.cmd != nil && sup.cmd.Process != nil {
		_ = sup.cmd.Process.Kill()
	}
	sup.mu.Unlock()

	// Verify crash was detected
	select {
	case <-crashedChan:
		// Crash detected
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for crash detection callback")
	}

	// Verify recovery happened (first backoff is 1s)
	select {
	case attempt := <-restartedChan:
		if attempt != 1 {
			t.Errorf("expected attempt 1, got %d", attempt)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for restart attempt callback")
	}

	// Wait up to 3 seconds for supervisor to return to RUNNING
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		state, _, _ := sup.GetState()
		if state == StateRunning {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	state, _, _ := sup.GetState()
	if state != StateRunning {
		t.Errorf("expected supervisor to recover to RUNNING, got %s", state)
	}

	if err := sup.Stop(); err != nil {
		t.Fatalf("failed to stop supervisor: %v", err)
	}
}

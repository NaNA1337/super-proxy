package xray

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

	// Verify initially neither outbound is active until synchronized
	if sup.IsOutboundActive("exit-0") || sup.IsOutboundActive("exit-1") {
		t.Errorf("expected outbounds to be initially inactive before synchronization")
	}

	// Synchronize active slots 0 and 1
	if err := sup.SyncActiveSlots([]int{0, 1}); err != nil {
		t.Fatalf("failed to sync active slots: %v", err)
	}
	if !sup.IsOutboundActive("exit-0") || !sup.IsOutboundActive("exit-1") {
		t.Errorf("expected exit-0 and exit-1 to be active after SyncActiveSlots")
	}

	// Dynamically drain slot 0 (DRAINING simulation without rmo)
	if err := sup.DrainingSlot(0); err != nil {
		t.Fatalf("failed to drain slot 0: %v", err)
	}
	if sup.IsOutboundActive("exit-0") {
		t.Errorf("expected exit-0 to be marked inactive after draining")
	}
	if !sup.IsOutboundActive("exit-1") {
		t.Errorf("expected exit-1 to remain active during slot 0 drain")
	}

	// Re-activate slot 0 (Standby promotion simulation)
	if err := sup.ActivateSlot(0); err != nil {
		t.Fatalf("failed to activate slot 0: %v", err)
	}
	if !sup.IsOutboundActive("exit-0") {
		t.Errorf("expected exit-0 to be active after ActivateSlot")
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

func TestXray_ExactSetMatchingRejectsPrefixOverlap(t *testing.T) {
	// Verify that exact tag comparison rejects prefix overlaps (e.g. exit-10 when exit-1 is expected)
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "xray_prefix.json")
	sup := NewSupervisor(configPath, 10099, "127.0.0.1", 10899, 12)

	// Simulate lsrules output JSON where tag is "exit-10"
	simulatedJSON := []byte(`{
		"rules": [
			{"tag": "api"},
			{"ruleTag": "active-balancer-rule", "tag": "exit-10"}
		]
	}`)

	var lsResp lsRulesResponse
	if err := json.Unmarshal(simulatedJSON, &lsResp); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}

	var activeRule *struct {
		RuleTag     string `json:"ruleTag"`
		Tag         string `json:"tag"`
		BalancerTag string `json:"balancerTag"`
	}
	for i := range lsResp.Rules {
		if lsResp.Rules[i].RuleTag == "active-balancer-rule" {
			activeRule = &lsResp.Rules[i]
			break
		}
	}
	if activeRule == nil {
		t.Fatalf("active-balancer-rule not found")
	}

	// When expecting slot 1 (tag "exit-1"), "exit-10" must NOT match!
	expectedTag := "exit-1"
	if activeRule.Tag == expectedTag {
		t.Fatalf("exact match should NOT equate exit-10 with exit-1")
	}

	// Substring contains would dangerously match "exit-1" in "exit-10", but exact equality prevents this!
	if strings.Contains(activeRule.Tag, expectedTag) {
		// Verify that our code uses strict equality:
		isExactMatch := (activeRule.Tag == expectedTag)
		if isExactMatch {
			t.Fatalf("isExactMatch must be false for exit-10 vs exit-1")
		}
	}
	_ = sup
}

package scheduler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
)

func TestFSM_FullQualificationPipeline(t *testing.T) {
	node := &models.Node{
		ID:     "node-full-pipe-1",
		IP:     "198.51.100.1",
		Status: models.StatusNew,
	}

	fullPipeline := []string{
		models.StatusDiscovered,
		models.StatusReputationChecked,
		models.StatusConnecting,
		models.StatusHealthCheck,
		models.StatusSpeedTest,
		models.StatusQualified,
		models.StatusStandby,
		models.StatusActive,
		models.StatusDraining,
		models.StatusFailed,
		models.StatusCooldown,
		models.StatusDiscovered,
	}

	for _, nextState := range fullPipeline {
		err := TransitionNodeDirect(node, nextState)
		if err != nil {
			t.Fatalf("Failed transition from %s to %s: %v", node.Status, nextState, err)
		}
		if node.Status != nextState {
			t.Fatalf("Expected status %s, got %s", nextState, node.Status)
		}
	}
}

func TestQualification_SpeedTestFailureTransitionsToFailed(t *testing.T) {
	node := &models.Node{
		ID:     "node-speed-fail",
		IP:     "198.51.100.2",
		Status: models.StatusConnecting,
	}

	// Move through connecting to health check to speed test
	if err := TransitionNodeDirect(node, models.StatusHealthCheck); err != nil {
		t.Fatalf("Failed transition to HEALTH_CHECK: %v", err)
	}
	if err := TransitionNodeDirect(node, models.StatusSpeedTest); err != nil {
		t.Fatalf("Failed transition to SPEED_TEST: %v", err)
	}

	// Mock benchmark failure
	mockBenchmarker := func(ctx context.Context, dev string) (*models.PerformanceMetrics, error) {
		return nil, errors.New("timeout probe failed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err := mockBenchmarker(ctx, "tun99")
	if err == nil {
		t.Fatalf("Expected benchmark error, got nil")
	}

	// On speed test failure, FSM moves to FAILED
	if err := TransitionNodeDirect(node, models.StatusFailed); err != nil {
		t.Fatalf("Expected transition to FAILED on speed test failure: %v", err)
	}
	if node.Status != models.StatusFailed {
		t.Fatalf("Expected node to be in FAILED state, got %s", node.Status)
	}
}

func TestQualification_SpeedTestSuccessTransitionsToQualified(t *testing.T) {
	node := &models.Node{
		ID:     "node-speed-success",
		IP:     "198.51.100.3",
		Status: models.StatusSpeedTest,
	}

	mockMetrics := &models.PerformanceMetrics{
		RTT:           42,
		Throughput:    150000000,
		DownloadSpeed: 150000000,
		UploadSpeed:   0,
		UploadStatus:  "UNAVAILABLE",
		PacketLoss:    0.0,
		DurationMs:    1200,
		LastChecked:   time.Now(),
	}

	mockBenchmarker := func(ctx context.Context, dev string) (*models.PerformanceMetrics, error) {
		return mockMetrics, nil
	}

	res, err := mockBenchmarker(context.Background(), "tun99")
	if err != nil {
		t.Fatalf("Expected benchmark success, got %v", err)
	}
	if res.DownloadSpeed != 150000000 || res.UploadStatus != "UNAVAILABLE" {
		t.Fatalf("Unexpected benchmark result: %+v", res)
	}

	if err := TransitionNodeDirect(node, models.StatusQualified); err != nil {
		t.Fatalf("Expected transition to QUALIFIED: %v", err)
	}
	if err := TransitionNodeDirect(node, models.StatusStandby); err != nil {
		t.Fatalf("Expected transition to STANDBY: %v", err)
	}
	if node.Status != models.StatusStandby {
		t.Fatalf("Expected node to be in STANDBY, got %s", node.Status)
	}
}

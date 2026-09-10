package benchmark

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestBenchmark_RealMetricsCalculation(t *testing.T) {
	var probeCount atomic.Int32
	var downloadBytes atomic.Int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rtt":
			probeCount.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
		case "/down":
			payload := make([]byte, 100000)
			downloadBytes.Add(int64(len(payload)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(payload)
		case "/up":
			written, _ := io.Copy(io.Discard, r.Body)
			if written > 0 {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusBadRequest)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	cfg := BenchmarkConfig{
		RTTTargetURL:  ts.URL + "/rtt",
		ICMPTarget:    "127.0.0.1",
		DownloadURL:   ts.URL + "/down",
		UploadURL:     ts.URL + "/up",
		DownloadBytes: 100000,
		UploadBytes:   10000,
		Timeout:       5 * time.Second,
	}

	// Use "lo" interface which exists on all Linux systems
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	metrics, err := BenchmarkInterfaceWithConfig(ctx, "lo", cfg)
	if err != nil {
		t.Fatalf("unexpected benchmark failure: %v", err)
	}

	if metrics.RTT < 0 {
		t.Errorf("expected RTT >= 0, got %d", metrics.RTT)
	}
	if metrics.Throughput <= 0 {
		t.Errorf("expected Throughput > 0, got %d", metrics.Throughput)
	}
	if metrics.SpeedStatus != StatusAvailable {
		t.Errorf("expected SpeedStatus AVAILABLE, got %s", metrics.SpeedStatus)
	}
	if metrics.PacketLossStatus != StatusAvailable {
		t.Errorf("expected PacketLossStatus AVAILABLE with ICMP ping, got %s", metrics.PacketLossStatus)
	}
	if metrics.PacketLoss < 0 {
		t.Errorf("expected non-negative packet loss, got %.1f", metrics.PacketLoss)
	}
	if metrics.UploadStatus != StatusAvailable {
		t.Errorf("expected UploadStatus AVAILABLE, got %s", metrics.UploadStatus)
	}
	if metrics.UploadSpeed <= 0 {
		t.Errorf("expected UploadSpeed > 0, got %d", metrics.UploadSpeed)
	}
}

func TestBenchmark_NoICMPTargetNeverReportsAvailable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	cfg := BenchmarkConfig{
		RTTTargetURL:  ts.URL,
		ICMPTarget:    "", // NO ICMP target
		DownloadURL:   ts.URL,
		DownloadBytes: 100,
		Timeout:       2 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	metrics, err := BenchmarkInterfaceWithConfig(ctx, "lo", cfg)
	if err != nil {
		t.Fatalf("unexpected benchmark failure: %v", err)
	}

	// Strict requirement: Without genuine ICMP measurement, packet loss must NOT be AVAILABLE or 0%
	if metrics.PacketLossStatus == StatusAvailable {
		t.Fatalf("PacketLossStatus must NOT be AVAILABLE when ICMP was not measured, got %s", metrics.PacketLossStatus)
	}
	if metrics.PacketLossStatus != StatusNotMeasured {
		t.Errorf("expected PacketLossStatus NOT_MEASURED, got %s", metrics.PacketLossStatus)
	}
	if metrics.PacketLoss != -1.0 {
		t.Errorf("expected PacketLoss -1.0 when unmeasured, got %.1f", metrics.PacketLoss)
	}
}

func TestBenchmark_UnmeasuredSpeedAndUpload(t *testing.T) {
	cfg := BenchmarkConfig{
		RTTTargetURL:  "",
		ICMPTarget:    "",
		DownloadURL:   "",
		UploadURL:     "",
		DownloadBytes: 0,
		UploadBytes:   0,
		Timeout:       1 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	metrics, err := BenchmarkInterfaceWithConfig(ctx, "lo", cfg)
	if err != nil {
		t.Fatalf("unexpected benchmark failure: %v", err)
	}

	if metrics.SpeedStatus != StatusNotMeasured {
		t.Errorf("expected SpeedStatus NOT_MEASURED, got %s", metrics.SpeedStatus)
	}
	if metrics.UploadStatus != StatusNotMeasured {
		t.Errorf("expected UploadStatus NOT_MEASURED, got %s", metrics.UploadStatus)
	}
	if metrics.PacketLossStatus != StatusNotMeasured {
		t.Errorf("expected PacketLossStatus NOT_MEASURED, got %s", metrics.PacketLossStatus)
	}
}

func TestBenchmark_AllProbesFailReturnsError(t *testing.T) {
	cfg := BenchmarkConfig{
		RTTTargetURL:  "http://127.0.0.1:59999/nonexistent", // unroutable / closed port
		DownloadURL:   "http://127.0.0.1:59999/down",
		UploadURL:     "http://127.0.0.1:59999/up",
		DownloadBytes: 1000,
		UploadBytes:   1000,
		Timeout:       1 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := BenchmarkInterfaceWithConfig(ctx, "lo", cfg)
	if err == nil {
		t.Fatalf("expected benchmark to return error when all probes fail, got nil")
	}
}

func TestBenchmark_ConfigurableMultiPingTargets(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	cfg := BenchmarkConfig{
		RTTTargetURL: ts.URL,
		ICMPTargets:  []string{"127.0.0.1", "127.0.0.2"},
		Timeout:      3 * time.Second,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	metrics, err := BenchmarkInterfaceWithConfig(ctx, "lo", cfg)
	if err != nil {
		t.Fatalf("unexpected benchmark failure: %v", err)
	}

	if metrics.PacketLossStatus != StatusAvailable {
		t.Errorf("expected PacketLossStatus AVAILABLE with multi-targets, got %s", metrics.PacketLossStatus)
	}
	if metrics.PacketLoss < 0 {
		t.Errorf("expected non-negative median packet loss, got %.1f", metrics.PacketLoss)
	}
}

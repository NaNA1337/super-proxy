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
			count := probeCount.Add(1)
			if count == 2 {
				// Drop the 2nd probe to verify packet loss calculation
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
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
	// We dropped 1 out of 5 probes: packet loss should be 20.0%
	expectedLoss := 20.0
	if metrics.PacketLoss != expectedLoss {
		t.Errorf("expected PacketLoss %.1f%%, got %.1f%%", expectedLoss, metrics.PacketLoss)
	}
	if metrics.UploadStatus != "AVAILABLE" {
		t.Errorf("expected UploadStatus AVAILABLE, got %s", metrics.UploadStatus)
	}
	if metrics.UploadSpeed <= 0 {
		t.Errorf("expected UploadSpeed > 0, got %d", metrics.UploadSpeed)
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

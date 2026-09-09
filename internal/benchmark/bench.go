package benchmark

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
)

// BenchmarkConfig defines endpoints and limits for node performance qualification.
type BenchmarkConfig struct {
	RTTTargetURL  string
	DownloadURL   string
	UploadURL     string
	DownloadBytes int64
	UploadBytes   int64
	Timeout       time.Duration
}

// DefaultBenchmarkConfig provides reliable production testing endpoints.
func DefaultBenchmarkConfig() BenchmarkConfig {
	return BenchmarkConfig{
		RTTTargetURL:  "https://1.1.1.1",
		DownloadURL:   "https://speed.cloudflare.com/__down?bytes=5000000",
		UploadURL:     "https://speed.cloudflare.com/__up",
		DownloadBytes: 5000000,
		UploadBytes:   1000000,
		Timeout:       15 * time.Second,
	}
}

// BenchmarkInterface evaluates RTT, download throughput, upload throughput, and test duration over a specific interface.
func BenchmarkInterface(ctx context.Context, interfaceName string) (*models.PerformanceMetrics, error) {
	return BenchmarkInterfaceWithConfig(ctx, interfaceName, DefaultBenchmarkConfig())
}

// BenchmarkInterfaceWithConfig executes performance benchmarks using a custom configuration.
func BenchmarkInterfaceWithConfig(ctx context.Context, interfaceName string, cfg BenchmarkConfig) (*models.PerformanceMetrics, error) {
	totalStart := time.Now()

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			controlErr := c.Control(func(fd uintptr) {
				err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, interfaceName)
			})
			if controlErr != nil {
				return controlErr
			}
			return err
		},
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext:       dialer.DialContext,
			DisableKeepAlives: true,
		},
		Timeout: cfg.Timeout,
	}

	// 1. RTT & Packet Loss Test (Probing endpoint across sequential probes)
	probeCount := 5
	successCount := 0
	var totalRTT int64
	var lastErr error

	probeTimeout := cfg.Timeout / time.Duration(probeCount)
	if probeTimeout > 2*time.Second {
		probeTimeout = 2 * time.Second
	} else if probeTimeout < 500*time.Millisecond {
		probeTimeout = 500 * time.Millisecond
	}

	for i := 0; i < probeCount; i++ {
		probeCtx, probeCancel := context.WithTimeout(ctx, probeTimeout)
		pStart := time.Now()
		reqRTT, err := http.NewRequestWithContext(probeCtx, "GET", cfg.RTTTargetURL, nil)
		if err == nil {
			respRTT, errDo := client.Do(reqRTT)
			if errDo == nil {
				if respRTT.StatusCode >= 200 && respRTT.StatusCode < 400 {
					_ = respRTT.Body.Close()
					successCount++
					totalRTT += time.Since(pStart).Milliseconds()
				} else {
					_ = respRTT.Body.Close()
					lastErr = fmt.Errorf("HTTP status %d", respRTT.StatusCode)
				}
			} else {
				lastErr = errDo
			}
		} else {
			lastErr = err
		}
		probeCancel()
	}

	if successCount == 0 {
		return nil, fmt.Errorf("all %d RTT probes failed on %s: %w", probeCount, interfaceName, lastErr)
	}

	rtt := int(totalRTT / int64(successCount))
	packetLossPct := (float64(probeCount-successCount) / float64(probeCount)) * 100.0

	// 2. Download Throughput Test
	dlStart := time.Now()
	reqDL, err := http.NewRequestWithContext(ctx, "GET", cfg.DownloadURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create download request: %w", err)
	}
	respDL, err := client.Do(reqDL)
	if err != nil {
		return nil, fmt.Errorf("download throughput test failed on %s: %w", interfaceName, err)
	}
	written, _ := io.Copy(io.Discard, respDL.Body)
	_ = respDL.Body.Close()
	dlDuration := time.Since(dlStart).Seconds()
	if dlDuration <= 0 {
		dlDuration = 0.001
	}
	downloadBps := int64(float64(written) * 8 / dlDuration)

	// 3. Upload Throughput Test (with strict UNAVAILABLE handling if unsupported)
	var uploadBps int64
	uploadStatus := "AVAILABLE"
	if cfg.UploadURL != "" && cfg.UploadBytes > 0 {
		payload := bytes.Repeat([]byte("X"), int(cfg.UploadBytes))
		ulStart := time.Now()
		reqUL, err := http.NewRequestWithContext(ctx, "POST", cfg.UploadURL, bytes.NewReader(payload))
		if err == nil {
			reqUL.Header.Set("Content-Type", "application/octet-stream")
			respUL, err := client.Do(reqUL)
			if err != nil || (respUL.StatusCode != http.StatusOK && respUL.StatusCode != http.StatusNoContent) {
				log.Printf("[Benchmark] Upload test unavailable or failed on %s (%v); marking UNAVAILABLE without faking", interfaceName, err)
				uploadStatus = "UNAVAILABLE"
				uploadBps = 0
			} else {
				_ = respUL.Body.Close()
				ulDuration := time.Since(ulStart).Seconds()
				if ulDuration <= 0 {
					ulDuration = 0.001
				}
				uploadBps = int64(float64(len(payload)) * 8 / ulDuration)
			}
		} else {
			uploadStatus = "UNAVAILABLE"
		}
	} else {
		uploadStatus = "UNAVAILABLE"
	}

	totalDuration := time.Since(totalStart).Milliseconds()
	log.Printf("[Benchmark] %s results: RTT=%dms, Loss=%.1f%%, Download=%d bps, Upload=%d bps (%s), Duration=%dms",
		interfaceName, rtt, packetLossPct, downloadBps, uploadBps, uploadStatus, totalDuration)

	return &models.PerformanceMetrics{
		RTT:           rtt,
		Throughput:    downloadBps,
		DownloadSpeed: downloadBps,
		UploadSpeed:   uploadBps,
		UploadStatus:  uploadStatus,
		PacketLoss:    packetLossPct,
		DurationMs:    totalDuration,
		LastChecked:   time.Now(),
	}, nil
}

package benchmark

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NaNA1337/super-proxy/internal/models"
)

// Metric status constants aliased from models
const (
	StatusAvailable   = models.MetricStatusAvailable
	StatusUnavailable = models.MetricStatusUnavailable
	StatusNotMeasured = models.MetricStatusNotMeasured
	StatusError       = models.MetricStatusError
)

// BenchmarkConfig defines endpoints and limits for node performance qualification.
type BenchmarkConfig struct {
	RTTTargetURL  string
	ICMPTarget    string // Host or IP to ping for true ICMP packet loss (e.g. "1.1.1.1" or "127.0.0.1")
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
		ICMPTarget:    "1.1.1.1",
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

// measureICMPPacketLoss measures genuine ICMP packet loss using ping bound to the specified interface.
// If ICMP is not measured or ping cannot run, it returns -1.0 and NOT_MEASURED/ERROR (never faking 0% or AVAILABLE).
func measureICMPPacketLoss(ctx context.Context, interfaceName, target string) (float64, string) {
	if target == "" {
		return -1.0, StatusNotMeasured
	}
	// Sanitize target and interface: must not contain shell/control characters
	if strings.ContainsAny(target, " \t\n\r;|&`$><(){}[]\"'\\") {
		return -1.0, StatusError
	}
	if strings.ContainsAny(interfaceName, " \t\n\r;|&`$><(){}[]\"'\\") {
		return -1.0, StatusError
	}

	cmd := exec.CommandContext(ctx, "ping", "-c", "5", "-W", "1", "-I", interfaceName, target)
	out, err := cmd.CombinedOutput()
	outStr := string(out)

	re := regexp.MustCompile(`(\d+(?:\.\d+)?)%\s+packet\s+loss`)
	matches := re.FindStringSubmatch(outStr)
	if len(matches) >= 2 {
		pct, parseErr := strconv.ParseFloat(matches[1], 64)
		if parseErr == nil {
			return pct, StatusAvailable
		}
	}

	if err != nil {
		if strings.Contains(outStr, "100% packet loss") || strings.Contains(outStr, "100.0% packet loss") {
			return 100.0, StatusAvailable
		}
		return -1.0, StatusError
	}
	return -1.0, StatusUnavailable
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

	// 1. RTT Probing
	rtt := -1
	if cfg.RTTTargetURL != "" {
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
		rtt = int(totalRTT / int64(successCount))
	}

	// 2. Genuine ICMP Packet Loss Measurement (Never fake AVAILABLE or 0% without ICMP)
	packetLossPct, packetLossStatus := measureICMPPacketLoss(ctx, interfaceName, cfg.ICMPTarget)

	// 3. Download Throughput Test
	var downloadBps int64
	speedStatus := StatusNotMeasured
	if cfg.DownloadURL != "" && cfg.DownloadBytes > 0 {
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
		if written > 0 {
			downloadBps = int64(float64(written) * 8 / dlDuration)
			speedStatus = StatusAvailable
		} else {
			downloadBps = 0
			speedStatus = StatusUnavailable
		}
	}

	// 4. Upload Throughput Test
	var uploadBps int64
	uploadStatus := StatusNotMeasured
	if cfg.UploadURL != "" && cfg.UploadBytes > 0 {
		payload := bytes.Repeat([]byte("X"), int(cfg.UploadBytes))
		ulStart := time.Now()
		reqUL, err := http.NewRequestWithContext(ctx, "POST", cfg.UploadURL, bytes.NewReader(payload))
		if err == nil {
			reqUL.Header.Set("Content-Type", "application/octet-stream")
			respUL, err := client.Do(reqUL)
			if err != nil || (respUL.StatusCode != http.StatusOK && respUL.StatusCode != http.StatusNoContent) {
				log.Printf("[Benchmark] Upload test unavailable or failed on %s (%v); marking UNAVAILABLE without faking", interfaceName, err)
				uploadStatus = StatusUnavailable
				uploadBps = 0
			} else {
				_ = respUL.Body.Close()
				ulDuration := time.Since(ulStart).Seconds()
				if ulDuration <= 0 {
					ulDuration = 0.001
				}
				uploadBps = int64(float64(len(payload)) * 8 / ulDuration)
				uploadStatus = StatusAvailable
			}
		} else {
			uploadStatus = StatusUnavailable
		}
	}

	totalDuration := time.Since(totalStart).Milliseconds()
	log.Printf("[Benchmark] %s results: RTT=%dms, Loss=%.1f%% (%s), Download=%d bps (%s), Upload=%d bps (%s), Duration=%dms",
		interfaceName, rtt, packetLossPct, packetLossStatus, downloadBps, speedStatus, uploadBps, uploadStatus, totalDuration)

	return &models.PerformanceMetrics{
		RTT:              rtt,
		Throughput:       downloadBps,
		DownloadSpeed:    downloadBps,
		UploadSpeed:      uploadBps,
		UploadStatus:     uploadStatus,
		SpeedStatus:      speedStatus,
		PacketLoss:       packetLossPct,
		PacketLossStatus: packetLossStatus,
		DurationMs:       totalDuration,
		LastChecked:      time.Now(),
	}, nil
}

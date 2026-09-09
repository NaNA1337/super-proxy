package benchmark

import (
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

func BenchmarkInterface(ctx context.Context, interfaceName string) (*models.PerformanceMetrics, error) {
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
		Timeout: 15 * time.Second, // Allow more time for speed test
	}

	// 1. RTT Test
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://1.1.1.1", nil)
	resp, err := client.Do(req)
	rtt := time.Since(start).Milliseconds()

	if err != nil {
		return nil, fmt.Errorf("RTT test failed on %s: %w", interfaceName, err)
	}
	resp.Body.Close()

	// 2. Throughput Test (Download 10MB test file from Cloudflare)
	start = time.Now()
	reqSpeed, _ := http.NewRequestWithContext(ctx, "GET", "https://speed.cloudflare.com/__down?bytes=10000000", nil)
	respSpeed, err := client.Do(reqSpeed)
	if err != nil {
		return nil, fmt.Errorf("Throughput test failed on %s: %w", interfaceName, err)
	}
	defer respSpeed.Body.Close()

	written, _ := io.Copy(io.Discard, respSpeed.Body)
	duration := time.Since(start).Seconds()

	throughputBps := int64(float64(written) * 8 / duration)

	log.Printf("[Benchmark] %s: RTT=%dms, Throughput=%d bps", interfaceName, rtt, throughputBps)

	return &models.PerformanceMetrics{
		RTT:         int(rtt),
		Throughput:  throughputBps,
		PacketLoss:  0.0, // Hard to calculate purely from HTTP, skipping for now
		LastChecked: time.Now(),
	}, nil
}

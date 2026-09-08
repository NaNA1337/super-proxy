package health

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// CheckTunnelConnectivity tests HTTP connectivity via a specific network interface
func CheckTunnelConnectivity(ctx context.Context, interfaceName string, testURL string) (bool, time.Duration, error) {
	// Create a dialer that binds to the specific interface
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			controlErr := c.Control(func(fd uintptr) {
				// SO_BINDTODEVICE requires root on Linux, which Controller should have.
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
			DialContext:           dialer.DialContext,
			DisableKeepAlives:     true,
			ExpectContinueTimeout: 1 * time.Second,
		},
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return false, 0, err
	}

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		return false, duration, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return true, duration, nil
	}

	return false, duration, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

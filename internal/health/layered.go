package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// LayeredHealthResult stores the result of the layered health check
type LayeredHealthResult struct {
	ProcessAlive bool
	TunUp        bool
	RouteReady   bool
	TCPReady     bool
	DNSReady     bool
	ExitIPValid  bool
	
	RTT        int     // in ms
	PacketLoss float64 // percentage
	
	Error error
}

// PerformLayeredCheck executes the health check chain
func PerformLayeredCheck(ctx context.Context, interfaceName string, expectedExitIP string, tableID int) *LayeredHealthResult {
	res := &LayeredHealthResult{}
	
	// 1. Process/Tun check
	/* #nosec G204 */
	cmd := exec.CommandContext(ctx, "ip", "link", "show", "dev", interfaceName)
	if err := cmd.Run(); err != nil {
		res.Error = fmt.Errorf("tun interface %s is not up: %w", interfaceName, err)
		return res
	}
	res.ProcessAlive = true
	res.TunUp = true

	// 2. Route Check
	/* #nosec G204 */
	cmd = exec.CommandContext(ctx, "ip", "route", "show", "table", fmt.Sprintf("%d", tableID))
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), interfaceName) {
		res.Error = fmt.Errorf("routing table %d does not have default route to %s", tableID, interfaceName)
		return res
	}
	res.RouteReady = true

	// 3. Setup Dialer
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				controlErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, interfaceName)
			})
			if err != nil {
				return err
			}
			return controlErr
		},
	}

	// 4. TCP/HTTPS Check
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:       dialer.DialContext,
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}

	// We use ipify to check both HTTPS connectivity and Exit IP at once
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org?format=json", nil)
	resp, err := client.Do(req)
	duration := time.Since(start)
	
	if err != nil {
		res.Error = fmt.Errorf("TCP/HTTPS connection failed on %s: %w", interfaceName, err)
		return res
	}
	defer resp.Body.Close()
	
	res.TCPReady = true
	res.DNSReady = true // implicitly passed if we resolved api.ipify.org
	res.RTT = int(duration.Milliseconds())
	
	var ipify struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ipify); err == nil {
		if ipify.IP == expectedExitIP {
			res.ExitIPValid = true
		} else {
			res.Error = fmt.Errorf("exit IP mismatch: expected %s, got %s", expectedExitIP, ipify.IP)
		}
	}

	return res
}

// Deprecated: CheckTunnelConnectivity is replaced by PerformLayeredCheck
func CheckTunnelConnectivity(ctx context.Context, interfaceName string, testURL string) (bool, time.Duration, error) {
	// Wrapper to not break older code instantly, though we should migrate it
	res := PerformLayeredCheck(ctx, interfaceName, "", 0)
	if res.Error != nil && res.Error.Error() != "exit IP mismatch: expected , got " { // ignore exit ip check
		return false, 0, res.Error
	}
	return true, time.Duration(res.RTT) * time.Millisecond, nil
}

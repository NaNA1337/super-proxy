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

	"github.com/NaNA1337/super-proxy/internal/models"
)

// VerifyResult defines the strict, unified output format of the health check
type VerifyResult struct {
	TunnelHealthy     bool
	Interface         string
	ObservedExitIP    string
	ExpectedExitIP    string
	ExitIPMatch       bool
	DNSOK             bool
	TCPConnectivity   bool
	HTTPSConnectivity bool
	Latency           time.Duration
	PacketLoss        float64
	Error             error
}

// VerifyTunnel is the ONLY official path for validating if a tunnel is ready for ACTIVE state.
// It executes Process -> tun -> Route -> TCP/HTTPS -> DNS -> Exit IP validation.
func VerifyTunnel(ctx context.Context, slot int, interfaceName string, tableID int, node *models.Node) *VerifyResult {
	res := &VerifyResult{
		Interface:      interfaceName,
		ExpectedExitIP: node.IP,
	}

	// 1. Process/Tun check
	/* #nosec G204 */
	cmd := exec.CommandContext(ctx, "ip", "link", "show", "dev", interfaceName)
	if err := cmd.Run(); err != nil {
		res.Error = fmt.Errorf("tun interface %s is not up: %w", interfaceName, err)
		return res
	}

	// 2. Route Check
	/* #nosec G204 */
	cmd = exec.CommandContext(ctx, "ip", "route", "show", "table", fmt.Sprintf("%d", tableID))
	output, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(output), interfaceName) {
		res.Error = fmt.Errorf("routing table %d does not have default route to %s", tableID, interfaceName)
		return res
	}

	// 3. Setup Dialer to force traffic through the specific TUN interface
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				// Requires CAP_NET_RAW / root
				controlErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, interfaceName)
			})
			if err != nil {
				return err
			}
			return controlErr
		},
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext:       dialer.DialContext,
			DisableKeepAlives: true,
		},
		Timeout: 10 * time.Second,
	}

	// 4. DNS + HTTPS + Exit IP Validation via ipify
	start := time.Now()
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.ipify.org?format=json", nil)
	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		res.Error = fmt.Errorf("TCP/HTTPS/DNS connection failed on %s: %w", interfaceName, err)
		return res
	}
	defer resp.Body.Close()

	res.TCPConnectivity = true
	res.HTTPSConnectivity = true
	res.DNSOK = true // implicitly passed if api.ipify.org resolved
	res.Latency = duration

	var ipify struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ipify); err != nil {
		res.Error = fmt.Errorf("failed to decode ipify response: %w", err)
		return res
	}

	res.ObservedExitIP = ipify.IP
	if res.ObservedExitIP == res.ExpectedExitIP {
		res.ExitIPMatch = true
		res.TunnelHealthy = true
	} else {
		res.Error = fmt.Errorf("exit IP mismatch: expected %s, got %s", res.ExpectedExitIP, res.ObservedExitIP)
	}

	return res
}

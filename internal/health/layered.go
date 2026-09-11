package health

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
		ExpectedExitIP: node.ObservedExitIP,
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
				if controlErr == nil {
					controlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, tableID)
				}
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
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Prohibit following external redirects to prevent redirection attacks
			return http.ErrUseLastResponse
		},
		Timeout: 10 * time.Second,
	}

	// 4. Multi-Provider DNS + HTTPS + Exit IP Validation with Failover
	providers := []struct {
		url    string
		isJSON bool
	}{
		{"https://api.ipify.org?format=json", true},
		{"https://ifconfig.me/ip", false},
		{"https://icanhazip.com", false},
	}

	var observedIP string
	var lastErr error
	var totalDuration time.Duration

	for _, p := range providers {
		start := time.Now()
		req, err := http.NewRequestWithContext(ctx, "GET", p.url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		// Modern User-Agent avoids Cloudflare/anti-bot blocks
		req.Header.Set("User-Agent", "curl/8.5.0")

		resp, err := client.Do(req)
		duration := time.Since(start)
		if err != nil {
			lastErr = fmt.Errorf("provider %s failed: %w", p.url, err)
			continue
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("provider %s read error: %w", p.url, err)
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = fmt.Errorf("provider %s returned HTTP %d", p.url, resp.StatusCode)
			continue
		}

		var candidateIP string
		if p.isJSON {
			var parsed struct {
				IP string `json:"ip"`
			}
			if err := json.Unmarshal(bodyBytes, &parsed); err == nil {
				candidateIP = strings.TrimSpace(parsed.IP)
			}
		} else {
			candidateIP = strings.TrimSpace(string(bodyBytes))
		}

		parsedIP := net.ParseIP(candidateIP)
		if parsedIP != nil && parsedIP.To4() != nil && parsedIP.IsGlobalUnicast() && !parsedIP.IsPrivate() {
			observedIP = candidateIP
			totalDuration = duration
			res.TCPConnectivity = true
			res.HTTPSConnectivity = true
			res.DNSOK = true
			res.Latency = totalDuration
			break
		} else {
			lastErr = fmt.Errorf("provider %s returned invalid exit IPv4: %q", p.url, candidateIP)
		}
	}

	if observedIP == "" {
		res.Error = fmt.Errorf("all exit IP verification providers failed on %s: %v", interfaceName, lastErr)
		return res
	}

	res.ObservedExitIP = observedIP

	// First qualification learns the egress through a device-bound, marked socket.
	// VPN Gate server endpoints can sit behind a different NAT egress address.
	if res.ExpectedExitIP == "" || res.ObservedExitIP == res.ExpectedExitIP {
		res.ExitIPMatch = true
		res.TunnelHealthy = true
	} else {
		res.Error = fmt.Errorf("exit IP mismatch: expected %s, got %s", res.ExpectedExitIP, res.ObservedExitIP)
	}

	return res
}

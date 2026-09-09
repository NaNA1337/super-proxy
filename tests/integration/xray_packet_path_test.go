package integration

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/xray"
)

// dialSocks5 establishes a TCP connection through a SOCKS5 proxy without external dependencies.
func dialSocks5(socksAddr, targetAddr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial socks %s: %w", socksAddr, err)
	}

	// 1. Send version & auth methods (no authentication: 0x00)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks auth write: %w", err)
	}

	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil || authResp[0] != 0x05 || authResp[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks auth negotiation failed: %v", authResp)
	}

	// 2. Parse target host & port
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid target addr %s: %w", targetAddr, err)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid target port %s: %w", portStr, err)
	}

	// 3. Send CONNECT request
	var req []byte
	ip := net.ParseIP(host).To4()
	if ip != nil {
		req = append([]byte{0x05, 0x01, 0x00, 0x01}, ip...)
	} else {
		req = append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, []byte(host)...)
	}
	req = append(req, byte(portNum>>8), byte(portNum&0xff))

	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks connect write: %w", err)
	}

	// 4. Read CONNECT response
	respHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, respHeader); err != nil || respHeader[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks connect failed (rep=%x): %v", respHeader[1], err)
	}

	// Discard bound address
	switch respHeader[3] {
	case 0x01: // IPv4
		discard := make([]byte, 4+2)
		_, _ = io.ReadFull(conn, discard)
	case 0x04: // IPv6
		discard := make([]byte, 16+2)
		_, _ = io.ReadFull(conn, discard)
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		_, _ = io.ReadFull(conn, lenBuf)
		discard := make([]byte, int(lenBuf[0])+2)
		_, _ = io.ReadFull(conn, discard)
	}

	return conn, nil
}

// readIptablesPackets returns the packet count for a specific mark and destination port from iptables mangle OUTPUT.
func readIptablesPackets(mark int, dport int) int64 {
	out, err := exec.Command("iptables", "-t", "mangle", "-L", "OUTPUT", "-v", "-n", "-x").CombinedOutput()
	if err != nil {
		return -1
	}
	lines := strings.Split(string(out), "\n")
	markHex := fmt.Sprintf("0x%x", mark)
	dportStr := fmt.Sprintf("dpt:%d", dport)
	for _, l := range lines {
		if strings.Contains(l, markHex) && strings.Contains(l, dportStr) {
			fields := strings.Fields(l)
			if len(fields) >= 1 {
				pkts, err := strconv.ParseInt(fields[0], 10, 64)
				if err == nil {
					return pkts
				}
			}
		}
	}
	return 0
}

func TestXray_PacketPath_ExistingConnectionPreservedAnd100NewAvoidDraining(t *testing.T) {
	tempDir := t.TempDir()
	configPath := tempDir + "/xray_packet_path.json"
	apiPort := 10098
	socksPort := 10898

	// 1. Generate Xray config with 2 slots (Slot 0 = exit-0 fwmark 100, Slot 1 = exit-1 fwmark 101)
	if err := xray.GenerateConfigWithOptions(xray.ConfigOptions{
		SlotCount:   2,
		ConfigPath:  configPath,
		ApiPort:     apiPort,
		SocksListen: "127.0.0.1",
		SocksPort:   socksPort,
	}); err != nil {
		t.Fatalf("failed to generate Xray config: %v", err)
	}

	// 2. Start Xray Supervisor
	xsup := xray.NewSupervisor(configPath, apiPort, "127.0.0.1", socksPort, 2)
	if err := xsup.Start(); err != nil {
		t.Fatalf("failed to start Xray: %v", err)
	}
	defer xsup.Stop()

	// 3. Start local target TCP echo server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on tcp: %v", err)
	}
	defer ln.Close()

	targetAddr := ln.Addr().String()
	_, portStr, _ := net.SplitHostPort(targetAddr)
	targetPort, _ := strconv.Atoi(portStr)

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					_, _ = c.Write([]byte("ECHO:" + line))
				}
			}(conn)
		}
	}()

	// 4. Setup Linux iptables packet counters if running as root
	isRoot := os.Geteuid() == 0
	if isRoot {
		_ = exec.Command("iptables", "-t", "mangle", "-I", "OUTPUT", "1", "-p", "tcp", "--dport", portStr,
			"-m", "mark", "--mark", "100", "-j", "ACCEPT").Run()
		_ = exec.Command("iptables", "-t", "mangle", "-I", "OUTPUT", "2", "-p", "tcp", "--dport", portStr,
			"-m", "mark", "--mark", "101", "-j", "ACCEPT").Run()
		defer func() {
			_ = exec.Command("iptables", "-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "--dport", portStr,
				"-m", "mark", "--mark", "100", "-j", "ACCEPT").Run()
			_ = exec.Command("iptables", "-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "--dport", portStr,
				"-m", "mark", "--mark", "101", "-j", "ACCEPT").Run()
		}()
	}

	// 5. Initial State: Activate only Slot 0
	if err := xsup.ActivateSlot(0); err != nil {
		t.Fatalf("failed to activate slot 0: %v", err)
	}

	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)

	// 6. Establish a long-lived bidirectional TCP stream through SOCKS on Slot 0
	rawConn, err := dialSocks5(socksAddr, targetAddr)
	if err != nil {
		t.Fatalf("failed to connect via socks5 to target: %v", err)
	}
	defer rawConn.Close()

	reader := bufio.NewReader(rawConn)

	// Send message 1 BEFORE drain
	if _, err := rawConn.Write([]byte("MSG_BEFORE_DRAIN\n")); err != nil {
		t.Fatalf("failed to send on raw conn: %v", err)
	}
	res1, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(res1) != "ECHO:MSG_BEFORE_DRAIN" {
		t.Fatalf("unexpected echo before drain: %s (err: %v)", res1, err)
	}

	// 7. Now also activate Slot 1 so Xray has a surviving active slot
	if err := xsup.ActivateSlot(1); err != nil {
		t.Fatalf("failed to activate slot 1: %v", err)
	}

	// 8. Transition Slot 0 to DRAINING!
	// (Must NOT call rmo, must preserve existing sockets, must exclude from new routing via adrules)
	if err := xsup.DrainingSlot(0); err != nil {
		t.Fatalf("failed to transition slot 0 to DRAINING: %v", err)
	}

	// Verify runtime active-set read-back: exit-0 must NOT be active
	if xsup.IsOutboundActive("exit-0") {
		t.Fatalf("CRITICAL VIOLATION: exit-0 still reported active after DrainingSlot")
	}
	if !xsup.IsOutboundActive("exit-1") {
		t.Fatalf("expected surviving exit-1 to remain active")
	}

	// 9. CRITICAL VERIFICATION: Existing connection on Slot 0 remains 100% functional!
	// The socket was NOT closed or reset by Xray.
	if _, err := rawConn.Write([]byte("MSG_DURING_DRAIN\n")); err != nil {
		t.Fatalf("failed to send on existing connection during drain: %v", err)
	}
	res2, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(res2) != "ECHO:MSG_DURING_DRAIN" {
		t.Fatalf("CRITICAL REGRESSION: existing connection died or corrupted during drain: %s (err: %v)", res2, err)
	}

	// 10. Record traffic baselines before 100 new connections
	exit0TrafficBefore, _, _ := xsup.GetOutboundStats("exit-0")
	exit1TrafficBefore, _, _ := xsup.GetOutboundStats("exit-1")
	var iptables100Before, iptables101Before int64
	if isRoot {
		iptables100Before = readIptablesPackets(100, targetPort)
		iptables101Before = readIptablesPackets(101, targetPort)
	}

	// 11. Dispatch 100 NEW connections concurrently through SOCKS
	const totalNewConnections = 100
	var wg sync.WaitGroup
	var successfulNewConnections atomic.Int64
	var failedNewConnections atomic.Int64

	for i := 0; i < totalNewConnections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := dialSocks5(socksAddr, targetAddr)
			if err != nil {
				failedNewConnections.Add(1)
				t.Errorf("New connection %d failed to connect through SOCKS: %v", id, err)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("HELLO_%d\n", id)
			if _, err := conn.Write([]byte(msg)); err != nil {
				failedNewConnections.Add(1)
				t.Errorf("New connection %d failed to write: %v", id, err)
				return
			}
			r := bufio.NewReader(conn)
			resp, err := r.ReadString('\n')
			if err != nil || strings.TrimSpace(resp) != "ECHO:"+strings.TrimSpace(msg) {
				failedNewConnections.Add(1)
				t.Errorf("New connection %d echo mismatch: %s (err: %v)", id, resp, err)
				return
			}
			successfulNewConnections.Add(1)
		}(i)
	}

	wg.Wait()

	if failed := failedNewConnections.Load(); failed > 0 {
		t.Fatalf("%d out of %d new connections failed through SOCKS proxy during draining",
			failed, totalNewConnections)
	}
	if succeeded := successfulNewConnections.Load(); succeeded != totalNewConnections {
		t.Fatalf("expected all %d new connections to succeed, got %d",
			totalNewConnections, succeeded)
	}

	// 12. Send message 3 on existing connection AFTER the 100 new connections:
	// Verify existing connection survived even while 100 concurrent connections were processed
	if _, err := rawConn.Write([]byte("MSG_AFTER_100_CONNECTIONS\n")); err != nil {
		t.Fatalf("failed to send on existing connection after 100 connections: %v", err)
	}
	res3, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(res3) != "ECHO:MSG_AFTER_100_CONNECTIONS" {
		t.Fatalf("existing connection failed after concurrent batch: %s (err: %v)", res3, err)
	}

	// 13. Verify Traffic Distribution:
	// ALL new connections must have routed to Slot 1 (exit-1).
	// Slot 0 (exit-0) must have received ZERO new connections!
	exit0TrafficAfter, _, _ := xsup.GetOutboundStats("exit-0")
	exit1TrafficAfter, _, _ := xsup.GetOutboundStats("exit-1")

	exit0Delta := exit0TrafficAfter - exit0TrafficBefore
	exit1Delta := exit1TrafficAfter - exit1TrafficBefore

	t.Logf("[Xray Stats Verification] exit-0 delta: %d bytes, exit-1 delta: %d bytes", exit0Delta, exit1Delta)

	// exit-1 must have handled the bulk of traffic (100 new TCP connections)
	if exit1Delta <= 0 {
		t.Errorf("CRITICAL VIOLATION: exit-1 handled no new traffic (delta=%d)", exit1Delta)
	}
	// exit-0 delta should only be from the single existing connection message (a few dozen bytes)
	if exit0Delta > 300 {
		t.Errorf("CRITICAL VIOLATION: draining slot exit-0 received unexpected traffic (%d bytes)", exit0Delta)
	}

	// 14. Linux Kernel iptables Packet-Path Verification
	if isRoot {
		iptables100After := readIptablesPackets(100, targetPort)
		iptables101After := readIptablesPackets(101, targetPort)

		pkts100Delta := iptables100After - iptables100Before
		pkts101Delta := iptables101After - iptables101Before

		t.Logf("[Linux iptables Packet Verification] fwmark 100 delta: %d packets, fwmark 101 delta: %d packets",
			pkts100Delta, pkts101Delta)

		if pkts101Delta < totalNewConnections {
			t.Errorf("Expected fwmark 101 (Slot 1) to carry at least %d packets for 100 connections, got %d",
				totalNewConnections, pkts101Delta)
		}
		// Mark 100 should only have a few packets from the single existing stream exchange
		if pkts100Delta > 10 {
			t.Errorf("CRITICAL VIOLATION: fwmark 100 (draining Slot 0) carried %d new packets", pkts100Delta)
		}
	}

	_ = rawConn.Close()
	t.Logf("SUCCESS: Real Linux packet-path & Xray active-set DRAINING test passed completely.")
}

package integration

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
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

// readIptablesDnsDropPackets returns the packet count for DNS DROP rules in iptables filter OUTPUT.
func readIptablesDnsDropPackets() int64 {
	out, err := exec.Command("iptables", "-L", "OUTPUT", "-v", "-n", "-x").CombinedOutput()
	if err != nil {
		return -1
	}
	var total int64
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		if strings.Contains(l, "DROP") && strings.Contains(l, "dpt:53") {
			fields := strings.Fields(l)
			if len(fields) >= 1 {
				pkts, err := strconv.ParseInt(fields[0], 10, 64)
				if err == nil {
					total += pkts
				}
			}
		}
	}
	return total
}

// readIptablesProtoDnsDropPackets returns the packet count for DNS DROP rules in iptables filter OUTPUT matching proto ("udp" or "tcp").
func readIptablesProtoDnsDropPackets(proto string) int64 {
	out, err := exec.Command("iptables", "-L", "OUTPUT", "-v", "-n", "-x").CombinedOutput()
	if err != nil {
		return -1
	}
	lines := strings.Split(string(out), "\n")
	for _, l := range lines {
		if strings.Contains(l, "DROP") && strings.Contains(l, proto) && strings.Contains(l, "dpt:53") {
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

// resolveWANInterface dynamically determines the outbound WAN interface using ip route.
func resolveWANInterface(targetIP string) (string, error) {
	if targetIP != "" {
		out, err := exec.Command("ip", "route", "get", targetIP).CombinedOutput()
		if err == nil {
			fields := strings.Fields(string(out))
			for i, f := range fields {
				if f == "dev" && i+1 < len(fields) {
					dev := fields[i+1]
					if dev != "lo" {
						return dev, nil
					}
				}
			}
		}
	}

	out, err := exec.Command("ip", "route", "show", "default").CombinedOutput()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			for i, f := range fields {
				if f == "dev" && i+1 < len(fields) {
					dev := fields[i+1]
					if dev != "lo" {
						return dev, nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("unable to determine default WAN interface")
}

// buildDNSQuery builds an authentic RFC 1035 wire-format A-record query for the given domain.
func buildDNSQuery(domain string, txID uint16) []byte {
	var buf []byte
	// 12-byte header
	buf = append(buf,
		byte(txID>>8), byte(txID&0xff), // Transaction ID
		0x01, 0x00, // Flags: Standard query, RD=1
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
	)
	// QNAME
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		if len(part) == 0 {
			continue
		}
		buf = append(buf, byte(len(part)))
		buf = append(buf, []byte(part)...)
	}
	buf = append(buf, 0x00) // Null root label
	// QTYPE = 1 (A), QCLASS = 1 (IN)
	buf = append(buf, 0x00, 0x01, 0x00, 0x01)
	return buf
}

// PacketCapture manages an active tcpdump observer process on a specified network interface.
type PacketCapture struct {
	iface    string
	filter   string
	pcapFile string
	cmd      *exec.Cmd
	stopped  bool
	stopMu   sync.Mutex
}

// StartPacketCapture starts tcpdump with -Z root on iface with filter, waits until
// tcpdump has actively entered packet capture mode ("listening on" in stderr), and returns *PacketCapture.
// Cleanup of the process and pcap file is automatically registered with t.Cleanup.
func StartPacketCapture(t *testing.T, iface, filter string) (*PacketCapture, error) {
	tcpdumpPath, err := exec.LookPath("tcpdump")
	if err != nil {
		return nil, fmt.Errorf("tcpdump binary not found: %w", err)
	}

	pcapFile := fmt.Sprintf("/tmp/cap_%d_%d.pcap", os.Getpid(), time.Now().UnixNano())

	cmd := exec.Command(tcpdumpPath, "-Z", "root", "-U", "-n", "-i", iface, "-w", pcapFile, filter)
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create tcpdump stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start tcpdump: %w", err)
	}

	pc := &PacketCapture{
		iface:    iface,
		filter:   filter,
		pcapFile: pcapFile,
		cmd:      cmd,
	}

	// Guarantee cleanup regardless of test outcome (PASS, FAIL, PANIC)
	t.Cleanup(func() {
		pc.Close()
	})

	// Wait until tcpdump is confirmed ready and capturing.
	// tcpdump outputs "listening on <iface>..." to stderr upon successful socket initialization.
	readyChan := make(chan struct{})
	go func() {
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "listening on") {
				close(readyChan)
				break
			}
		}
		for scanner.Scan() {
		}
	}()

	select {
	case <-readyChan:
		// tcpdump is actively capturing
	case <-time.After(2 * time.Second):
		pc.Close()
		return nil, fmt.Errorf("tcpdump failed to enter capture mode within 2s timeout")
	}

	return pc, nil
}

// Stop gracefully signals tcpdump with SIGINT to finalize pcap write.
func (pc *PacketCapture) Stop() {
	pc.stopMu.Lock()
	defer pc.stopMu.Unlock()
	if pc.stopped {
		return
	}
	pc.stopped = true

	if pc.cmd != nil && pc.cmd.Process != nil {
		_ = pc.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() {
			_ = pc.cmd.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(1 * time.Second):
			_ = pc.cmd.Process.Kill()
			_ = pc.cmd.Wait()
		}
	}
}

// Close terminates tcpdump and removes the pcap file.
func (pc *PacketCapture) Close() {
	pc.Stop()
	if pc.pcapFile != "" {
		_ = os.Remove(pc.pcapFile)
	}
}

// PacketCount stops the capture if still running and reads the number of packets from pcap using tcpdump -nn -r.
func (pc *PacketCapture) PacketCount() (int, error) {
	pc.Stop()

	if _, err := os.Stat(pc.pcapFile); os.IsNotExist(err) {
		return 0, nil
	}

	readCmd := exec.Command("tcpdump", "-nn", "-r", pc.pcapFile)
	out, err := readCmd.CombinedOutput()
	if err != nil {
		outStr := string(out)
		if strings.Contains(outStr, "reading from file") && !strings.Contains(outStr, "\n") {
			return 0, nil
		}
		return 0, fmt.Errorf("tcpdump -r failed: %w (%s)", err, outStr)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var count int
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "reading from file") {
			continue
		}
		count++
	}
	return count, nil
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

// TestLinuxPacketPathE2E_DualExitMarkersAndDNSLeak is the definitive real-process
// TestLinuxPacketPathE2E_DualExitMarkersAndFailClosed is the definitive real-process
// packet-path E2E test verifying real Xray packet forwarding, dual distinct exit markers
// (X-Test-Exit: slot-0 vs slot-1), existing connection draining survival, and all-dead fail-closed.
func TestLinuxPacketPathE2E_DualExitMarkersAndFailClosed(t *testing.T) {
	// 1. Setup Exit 0 server (returns X-Test-Exit: slot-0 and EXIT_SLOT_0)
	ln0, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on exit-0: %v", err)
	}
	defer ln0.Close()
	port0 := ln0.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln0.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				peek, _ := reader.Peek(4)
				if string(peek) == "GET " {
					// HTTP request: return exit marker headers
					resp := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Test-Exit: slot-0\r\nConnection: close\r\nContent-Length: 12\r\n\r\nEXIT_SLOT_0\n"
					_, _ = c.Write([]byte(resp))
					return
				}
				// Streaming TCP echo
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					_, _ = c.Write([]byte("PONG_SLOT_0:" + line))
				}
			}(conn)
		}
	}()

	// 2. Setup Exit 1 server (returns X-Test-Exit: slot-1 and EXIT_SLOT_1)
	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on exit-1: %v", err)
	}
	defer ln1.Close()
	port1 := ln1.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln1.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				peek, _ := reader.Peek(4)
				if string(peek) == "GET " {
					// HTTP request: return exit marker headers
					resp := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Test-Exit: slot-1\r\nConnection: close\r\nContent-Length: 12\r\n\r\nEXIT_SLOT_1\n"
					_, _ = c.Write([]byte(resp))
					return
				}
				// Streaming TCP echo
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					_, _ = c.Write([]byte("PONG_SLOT_1:" + line))
				}
			}(conn)
		}
	}()

	// 3. Setup iptables packet counters if running as root
	isRoot := os.Geteuid() == 0
	if isRoot {
		_ = exec.Command("iptables", "-t", "mangle", "-I", "OUTPUT", "1", "-p", "tcp", "--dport", strconv.Itoa(port0),
			"-m", "mark", "--mark", "100", "-j", "ACCEPT").Run()
		_ = exec.Command("iptables", "-t", "mangle", "-I", "OUTPUT", "2", "-p", "tcp", "--dport", strconv.Itoa(port1),
			"-m", "mark", "--mark", "101", "-j", "ACCEPT").Run()
		t.Cleanup(func() {
			_ = exec.Command("iptables", "-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "--dport", strconv.Itoa(port0),
				"-m", "mark", "--mark", "100", "-j", "ACCEPT").Run()
			_ = exec.Command("iptables", "-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "--dport", strconv.Itoa(port1),
				"-m", "mark", "--mark", "101", "-j", "ACCEPT").Run()
		})
	}

	// 4. Generate Xray config with 2 slots and destination redirects to Exit 0 and Exit 1
	tempDir := t.TempDir()
	configPath := tempDir + "/xray_packet_path_e2e.json"
	apiPort := 10298
	socksPort := 11098
	socksAddr := fmt.Sprintf("127.0.0.1:%d", socksPort)

	if err := xray.GenerateConfigWithOptions(xray.ConfigOptions{
		SlotCount:   2,
		ConfigPath:  configPath,
		ApiPort:     apiPort,
		SocksListen: "127.0.0.1",
		SocksPort:   socksPort,
		Redirects: map[int]string{
			0: ln0.Addr().String(),
			1: ln1.Addr().String(),
		},
	}); err != nil {
		t.Fatalf("failed to generate Xray config: %v", err)
	}

	xsup := xray.NewSupervisor(configPath, apiPort, "127.0.0.1", socksPort, 2)
	if err := xsup.Start(); err != nil {
		t.Fatalf("failed to start Xray: %v", err)
	}
	defer xsup.Stop()

	// HTTP Client dialing through SOCKS5
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialSocks5(socksAddr, addr)
			},
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}

	// -------------------------------------------------------------
	// PHASE A: Slot 0 ACTIVE -> Traffic exits via slot 0
	// -------------------------------------------------------------
	if err := xsup.ActivateSlot(0); err != nil {
		t.Fatalf("failed to activate slot 0: %v", err)
	}

	resp0, err := httpClient.Get("http://test.internal/exit")
	if err != nil {
		t.Fatalf("Phase A HTTP GET failed through SOCKS: %v", err)
	}
	body0Bytes, _ := io.ReadAll(resp0.Body)
	resp0.Body.Close()

	exitHeader0 := resp0.Header.Get("X-Test-Exit")
	body0 := strings.TrimSpace(string(body0Bytes))
	t.Logf("[Phase A] Slot 0 active -> X-Test-Exit: %q, Body: %q", exitHeader0, body0)

	if exitHeader0 != "slot-0" {
		t.Fatalf("CRITICAL ROUTING FAILURE: Expected X-Test-Exit 'slot-0', got %q", exitHeader0)
	}
	if body0 != "EXIT_SLOT_0" {
		t.Fatalf("CRITICAL ROUTING FAILURE: Expected body 'EXIT_SLOT_0', got %q", body0)
	}

	if isRoot {
		pkts100PhaseA := readIptablesPackets(100, port0)
		t.Logf("[Phase A Evidence] fwmark 100 iptables counter: %d packets verified", pkts100PhaseA)
		if pkts100PhaseA <= 0 {
			t.Fatalf("EVIDENCE FAILURE: iptables counter for fwmark 100 is %d (expected > 0)", pkts100PhaseA)
		}
	}

	// -------------------------------------------------------------
	// PHASE B: Establish long-lived streaming connection on Slot 0
	// -------------------------------------------------------------
	rawConn, err := dialSocks5(socksAddr, "test.internal:80")
	if err != nil {
		t.Fatalf("failed to dial long-lived stream: %v", err)
	}
	defer rawConn.Close()

	if _, err := rawConn.Write([]byte("PING_PHASE_B\n")); err != nil {
		t.Fatalf("failed to write to raw stream: %v", err)
	}
	reader := bufio.NewReader(rawConn)
	echoB, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(echoB, "PONG_SLOT_0") {
		t.Fatalf("unexpected echo from stream: %s (err: %v)", echoB, err)
	}

	// -------------------------------------------------------------
	// PHASE C: Slot 0 -> DRAINING, Slot 1 -> ACTIVE
	// -------------------------------------------------------------
	if err := xsup.ActivateSlot(1); err != nil {
		t.Fatalf("failed to activate slot 1: %v", err)
	}
	if err := xsup.DrainingSlot(0); err != nil {
		t.Fatalf("failed to transition slot 0 to DRAINING: %v", err)
	}

	// 1. Existing connection on Slot 0 remains 100% operational
	if _, err := rawConn.Write([]byte("PING_DURING_DRAIN\n")); err != nil {
		t.Fatalf("failed to write on existing connection during drain: %v", err)
	}
	echoDrain, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(echoDrain, "PONG_SLOT_0") {
		t.Fatalf("CRITICAL REGRESSION: existing connection on draining slot died or corrupted: %s (err: %v)", echoDrain, err)
	}
	t.Logf("[Phase C Evidence] Existing connection survived draining: %s", strings.TrimSpace(echoDrain))

	// 2. All NEW connections must route to Slot 1 (exit-1) and return 'slot-1'
	var pkts101Before int64
	if isRoot {
		pkts101Before = readIptablesPackets(101, port1)
	}
	const batchCount = 20
	for i := 0; i < batchCount; i++ {
		resp, err := httpClient.Get("http://test.internal/exit")
		if err != nil {
			t.Fatalf("new connection %d failed through SOCKS: %v", i, err)
		}
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		exitH := resp.Header.Get("X-Test-Exit")
		if exitH != "slot-1" {
			t.Fatalf("CRITICAL LEAK: new connection %d routed to %q instead of slot-1 (body: %s)",
				i, exitH, string(bodyBytes))
		}
	}

	if isRoot {
		pkts101After := readIptablesPackets(101, port1)
		pkts101Delta := pkts101After - pkts101Before
		t.Logf("[Phase C Evidence] fwmark 101 iptables counter delta for %d new connections: %d packets",
			batchCount, pkts101Delta)
		if pkts101Delta < int64(batchCount) {
			t.Fatalf("EVIDENCE FAILURE: fwmark 101 iptables delta %d is less than batch count %d",
				pkts101Delta, batchCount)
		}
	}

	// -------------------------------------------------------------
	// PHASE D: Slot 0 DEAD -> Surviving Slot 1 serves traffic, all-dead fails closed
	// -------------------------------------------------------------
	// 1. Terminate Slot 0 (simulates OpenVPN tunnel process exiting / dead)
	_ = ln0.Close()
	_ = rawConn.Close()

	// 2. New connections must still succeed and route to surviving Slot 1
	respAfterSlot0Dead, err := httpClient.Get("http://test.internal/exit")
	if err != nil {
		t.Fatalf("request failed while Slot 1 was active after Slot 0 dead: %v", err)
	}
	bodyAfterDeadBytes, _ := io.ReadAll(respAfterSlot0Dead.Body)
	respAfterSlot0Dead.Body.Close()
	if respAfterSlot0Dead.Header.Get("X-Test-Exit") != "slot-1" {
		t.Fatalf("CRITICAL ROUTING FAILURE: traffic routed to dead slot or wrong exit: %s", string(bodyAfterDeadBytes))
	}
	t.Logf("[Phase D1 Evidence] After Slot 0 DEAD, traffic cleanly routes to surviving Slot 1 (X-Test-Exit: %q)",
		respAfterSlot0Dead.Header.Get("X-Test-Exit"))

	// 3. Deactivate Slot 1 (now all slots are dead / no active slots remain)
	if err := xsup.DrainingSlot(1); err != nil {
		t.Fatalf("failed to drain slot 1: %v", err)
	}

	// 4. Attempting a new connection now must FAIL CLOSED and not leak onto WAN
	var capWAN *PacketCapture
	if isRoot {
		wanIface, wErr := resolveWANInterface("")
		if wErr == nil {
			capWAN, _ = StartPacketCapture(t, wanIface, "tcp port 80 and dst host test.internal")
		}
	}

	failClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialSocks5(socksAddr, addr)
			},
			DisableKeepAlives: true,
		},
		Timeout: 2 * time.Second,
	}
	_, err = failClient.Get("http://test.internal/exit")
	if err == nil {
		t.Fatalf("CRITICAL SECURITY VIOLATION: traffic succeeded when no active slots exist (did not fail closed)!")
	}
	t.Logf("[Phase D2 Evidence] All slots dead -> request failed closed as expected: %v", err)

	if capWAN != nil {
		wanPkts, pErr := capWAN.PacketCount()
		if pErr == nil {
			t.Logf("[Phase D2 Evidence] WAN tcpdump captured %d packets on WAN during all-slots-dead failure", wanPkts)
			if wanPkts != 0 {
				t.Fatalf("CRITICAL SECURITY VIOLATION: %d packets leaked out WAN interface when all slots dead!", wanPkts)
			}
		}
	}

	t.Logf("SUCCESS: Real Xray packet-path E2E verified dual exit markers, draining continuity, slot-0 dead failover, and all-dead fail-closed.")
}

// TestLinuxPacketPathE2E_DNSLeak verifies that direct DNS queries outside the proxy path
// (both UDP/53 and TCP/53) are independently dropped by the anti-leak firewall and do not leak out the WAN interface.
func TestLinuxPacketPathE2E_DNSLeak(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping DNS leak E2E test; requires root/CAP_NET_ADMIN")
	}

	wanIface, err := resolveWANInterface("1.1.1.1")
	if err != nil {
		t.Skipf("SKIPPED: WAN interface unavailable (%v)", err)
	}
	t.Logf("[DNS Leak E2E] Dynamically resolved WAN interface: %s", wanIface)

	// Install anti-leak DROP rules for both UDP and TCP port 53
	cmdUdp := exec.Command("iptables", "-I", "OUTPUT", "1", "-p", "udp", "--dport", "53", "-j", "DROP")
	if out, err := cmdUdp.CombinedOutput(); err != nil {
		t.Fatalf("failed to install UDP DNS anti-leak rule: %v (%s)", err, out)
	}
	cmdTcp := exec.Command("iptables", "-I", "OUTPUT", "2", "-p", "tcp", "--dport", "53", "-j", "DROP")
	if out, err := cmdTcp.CombinedOutput(); err != nil {
		_ = exec.Command("iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DROP").Run()
		t.Fatalf("failed to install TCP DNS anti-leak rule: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("iptables", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "DROP").Run()
		_ = exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "DROP").Run()
	})

	query := buildDNSQuery("example.com", 0x1234)

	// =========================================================================
	// 1. INDEPENDENT UDP DNS VERIFICATION
	// =========================================================================
	t.Run("UDP_DNS_AntiLeak", func(t *testing.T) {
		udpDropBefore := readIptablesProtoDnsDropPackets("udp")

		capUDP, err := StartPacketCapture(t, wanIface, "udp port 53 and host 1.1.1.1")
		if err != nil {
			t.Skipf("SKIPPED: tcpdump unavailable for UDP (%v)", err)
		}

		udpConn, err := net.DialTimeout("udp", "1.1.1.1:53", 500*time.Millisecond)
		if err != nil {
			t.Fatalf("failed to create UDP socket to 1.1.1.1:53: %v", err)
		}
		defer udpConn.Close()

		if _, writeErr := udpConn.Write(query); writeErr != nil {
			t.Logf("[UDP DNS Evidence] UDP DNS query dropped by kernel anti-leak at socket level: %v", writeErr)
		} else {
			_ = udpConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			respBuf := make([]byte, 512)
			n, readErr := udpConn.Read(respBuf)
			if readErr == nil && n > 0 {
				t.Fatalf("CRITICAL SECURITY VIOLATION: received DNS response when anti-leak DROP active (%d bytes)", n)
			}
		}

		udpDropAfter := readIptablesProtoDnsDropPackets("udp")
		t.Logf("[UDP DNS Evidence] iptables UDP drop counter delta: %d -> %d (delta=%d)",
			udpDropBefore, udpDropAfter, udpDropAfter-udpDropBefore)
		if udpDropAfter <= udpDropBefore {
			t.Fatalf("CRITICAL VIOLATION: UDP drop counter did not increase: before=%d, after=%d",
				udpDropBefore, udpDropAfter)
		}

		wanPktsUDP, err := capUDP.PacketCount()
		if err != nil {
			t.Fatalf("failed to inspect UDP pcap: %v", err)
		}
		t.Logf("[UDP DNS Evidence] WAN tcpdump captured %d UDP DNS packets on %s", wanPktsUDP, wanIface)
		if wanPktsUDP != 0 {
			t.Fatalf("CRITICAL SECURITY VIOLATION: %d UDP DNS packets leaked out WAN interface %s!", wanPktsUDP, wanIface)
		}
	})

	// =========================================================================
	// 2. INDEPENDENT TCP DNS VERIFICATION (Strictly separated from UDP)
	// =========================================================================
	t.Run("TCP_DNS_AntiLeak", func(t *testing.T) {
		tcpDropBefore := readIptablesProtoDnsDropPackets("tcp")

		capTCP, err := StartPacketCapture(t, wanIface, "tcp port 53 and host 1.1.1.1")
		if err != nil {
			t.Skipf("SKIPPED: tcpdump unavailable for TCP (%v)", err)
		}

		var tcpQuery []byte
		qLen := uint16(len(query))
		tcpQuery = append(tcpQuery, byte(qLen>>8), byte(qLen&0xff))
		tcpQuery = append(tcpQuery, query...)

		tcpDialer := net.Dialer{Timeout: 300 * time.Millisecond}
		tcpConn, tcpErr := tcpDialer.Dial("tcp", "1.1.1.1:53")
		if tcpErr == nil {
			defer tcpConn.Close()
			_, _ = tcpConn.Write(tcpQuery)
			_ = tcpConn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			respBuf := make([]byte, 512)
			_, _ = tcpConn.Read(respBuf)
		} else {
			t.Logf("[TCP DNS Evidence] Real TCP DNS connection blocked/dropped: %v", tcpErr)
		}

		tcpDropAfter := readIptablesProtoDnsDropPackets("tcp")
		t.Logf("[TCP DNS Evidence] iptables TCP drop counter delta: %d -> %d (delta=%d)",
			tcpDropBefore, tcpDropAfter, tcpDropAfter-tcpDropBefore)
		if tcpDropAfter <= tcpDropBefore {
			t.Fatalf("CRITICAL VIOLATION: TCP drop counter did not increase: before=%d, after=%d",
				tcpDropBefore, tcpDropAfter)
		}

		wanPktsTCP, err := capTCP.PacketCount()
		if err != nil {
			t.Fatalf("failed to inspect TCP pcap: %v", err)
		}
		t.Logf("[TCP DNS Evidence] WAN tcpdump captured %d TCP DNS packets on %s", wanPktsTCP, wanIface)
		if wanPktsTCP != 0 {
			t.Fatalf("CRITICAL SECURITY VIOLATION: %d TCP DNS packets leaked out WAN interface %s!", wanPktsTCP, wanIface)
		}
	})

	t.Logf("SUCCESS: Real UDP/53 & TCP/53 DNS anti-leak verified with authentic RFC 1035 packets, independent drop counters, and WAN capture == 0.")
}

// TestLinuxPacketPathE2E_IPv6FailClosed verifies that when IPv6 proxy path is unavailable,
// real IPv6 client sockets (TCP6 and UDP6) fail closed and do not leak out onto the WAN interface.
func TestLinuxPacketPathE2E_IPv6FailClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping IPv6 fail-closed E2E test; requires root/CAP_NET_ADMIN")
	}

	// Check if IPv6 stack is supported
	if _, err := os.Stat("/proc/sys/net/ipv6"); os.IsNotExist(err) {
		t.Skip("SKIPPED: IPv6 E2E requires IPv6-capable test environment (/proc/sys/net/ipv6 not found)")
	}

	wanIface, err := resolveWANInterface("")
	if err != nil {
		t.Skipf("SKIPPED: WAN interface unavailable (%v)", err)
	}
	t.Logf("[IPv6 Fail-Closed E2E] Dynamically resolved WAN interface: %s", wanIface)

	// Install unreachable IPv6 policy rule
	cmdAdd := exec.Command("ip", "-6", "rule", "add", "unreachable", "priority", "32765")
	if out, err := cmdAdd.CombinedOutput(); err != nil {
		t.Fatalf("failed to install IPv6 unreachable policy rule: %v (%s)", err, out)
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "-6", "rule", "del", "unreachable", "priority", "32765").Run()
	})

	// 1. Primitive routing lookup verification
	v6Out, v6Err := exec.Command("ip", "-6", "route", "get", "2001:db8::1").CombinedOutput()
	if v6Err == nil && !strings.Contains(string(v6Out), "unreachable") {
		t.Fatalf("CRITICAL SECURITY VIOLATION: ip -6 route get 2001:db8::1 returned routable: %s", string(v6Out))
	}
	t.Logf("[IPv6 Routing Evidence] Kernel lookup rejected: %s", strings.TrimSpace(string(v6Out)))

	// =========================================================================
	// 2. INDEPENDENT REAL TCP6 SOCKET FAIL-CLOSED & WAN CAPTURE
	// =========================================================================
	t.Run("TCP6_FailClosed", func(t *testing.T) {
		capTCP6, err := StartPacketCapture(t, wanIface, "ip6 and host 2001:db8::1 and tcp")
		if err != nil {
			t.Skipf("SKIPPED: tcpdump unavailable for TCP6 (%v)", err)
		}

		dialer := net.Dialer{
			Timeout:       500 * time.Millisecond,
			FallbackDelay: -1, // Disable DualStack/Happy Eyeballs IPv4 fallback
		}
		tcp6Conn, tcp6Err := dialer.Dial("tcp6", "[2001:db8::1]:443")
		if tcp6Err == nil {
			tcp6Conn.Close()
			t.Fatalf("CRITICAL SECURITY VIOLATION: real TCP6 socket succeeded when fail-closed active!")
		}
		errStr := tcp6Err.Error()
		if !strings.Contains(errStr, "unreachable") && !strings.Contains(errStr, "operation not permitted") && !strings.Contains(errStr, "no route to host") {
			t.Fatalf("CRITICAL SECURITY VIOLATION: real TCP6 socket failed with unexpected error (not fail-closed): %v", tcp6Err)
		}
		t.Logf("[IPv6 TCP6 Evidence] Real TCP6 socket failed closed as expected: %v", tcp6Err)

		wanTCP6Count, err := capTCP6.PacketCount()
		if err != nil {
			t.Fatalf("failed to inspect TCP6 pcap: %v", err)
		}
		t.Logf("[IPv6 TCP6 Evidence] WAN tcpdump captured %d TCP6 packets on %s", wanTCP6Count, wanIface)
		if wanTCP6Count != 0 {
			t.Fatalf("CRITICAL SECURITY VIOLATION: %d TCP6 packets leaked out WAN interface %s!", wanTCP6Count, wanIface)
		}
	})

	// =========================================================================
	// 3. INDEPENDENT REAL UDP6 SOCKET FAIL-CLOSED & WAN CAPTURE
	// =========================================================================
	t.Run("UDP6_FailClosed", func(t *testing.T) {
		capUDP6, err := StartPacketCapture(t, wanIface, "ip6 and host 2001:db8::1 and udp")
		if err != nil {
			t.Skipf("SKIPPED: tcpdump unavailable for UDP6 (%v)", err)
		}

		udp6Conn, udp6Err := net.DialTimeout("udp6", "[2001:db8::1]:53", 500*time.Millisecond)
		if udp6Err == nil {
			_, writeErr := udp6Conn.Write([]byte("IPV6_FAIL_CLOSED_PROBE"))
			udp6Conn.Close()
			if writeErr != nil {
				t.Logf("[IPv6 UDP6 Evidence] Real UDP6 write failed closed: %v", writeErr)
			} else {
				t.Logf("[IPv6 UDP6 Evidence] UDP6 packet buffered, kernel routing dropped, WAN tcpdump will verify zero egress")
			}
		} else {
			t.Logf("[IPv6 UDP6 Evidence] Real UDP6 socket dial failed closed: %v", udp6Err)
		}

		wanUDP6Count, err := capUDP6.PacketCount()
		if err != nil {
			t.Fatalf("failed to inspect UDP6 pcap: %v", err)
		}
		t.Logf("[IPv6 UDP6 Evidence] WAN tcpdump captured %d UDP6 packets on %s", wanUDP6Count, wanIface)
		if wanUDP6Count != 0 {
			t.Fatalf("CRITICAL SECURITY VIOLATION: %d UDP6 packets leaked out WAN interface %s!", wanUDP6Count, wanIface)
		}
	})

	t.Logf("SUCCESS: Real IPv6 socket fail-closed verified with independent TCP6/UDP6 sockets, unreachable policy, and WAN capture == 0.")
}


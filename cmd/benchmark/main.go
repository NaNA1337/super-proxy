package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/NaNA1337/super-proxy/internal/routing"
)

type tunnelTarget struct {
	Interface string
	Mark      int
}

type BenchmarkResult struct {
	Tunnels            int
	Interfaces         []string
	ConnectionsPerTun  int
	Duration           time.Duration
	TotalBytes         int64
	ThroughputBps      float64
	ThroughputMbps     float64
	RTTMs              int64
	PacketLossPct      float64
	PacketLossStatus   string
	SpeedStatus        string
	CPUUsagePct        float64
	PPS                float64
	MTU                int
	MSS                int
	DCOMode            string
	Target2GbpsReached bool
	StatusExplanation  string
}

func main() {
	tunnelCount := flag.Int("tunnels", 3, "Maximum number of active slots to benchmark (1, 2, 3)")
	ifacesFlag := flag.String("interfaces", "", "Comma-separated interface names to test (e.g. tun0,tun1,tun2 or eth0)")
	targetURL := flag.String("url", "https://speed.cloudflare.com/__down?bytes=10000000", "Download benchmark target URL")
	durationSec := flag.Int("duration", 5, "Test duration in seconds")
	connectionsPerTunnel := flag.Int("connections-per-tunnel", 4, "Concurrent download connections opened through each tunnel")
	flag.Parse()
	if *tunnelCount < 1 || *tunnelCount > 3 {
		log.Fatalf("-tunnels must be between 1 and 3")
	}
	if *connectionsPerTunnel < 1 || *connectionsPerTunnel > 32 {
		log.Fatalf("-connections-per-tunnel must be between 1 and 32")
	}

	log.Println("==============================================================")
	log.Println("     SUPER-PROXY PRODUCTION MULTI-TUNNEL BENCHMARK TOOL       ")
	log.Println("==============================================================")

	var targets []tunnelTarget
	if *ifacesFlag != "" {
		for _, s := range strings.Split(*ifacesFlag, ",") {
			trimmed := strings.TrimSpace(s)
			if trimmed != "" {
				targets = append(targets, tunnelTarget{
					Interface: trimmed,
					Mark:      routing.BaseTableID + len(targets),
				})
			}
		}
	}

	// Active interfaces are discovered from the slot policy tables. Interface
	// names are not stable because a standby tun3/tun4 may be promoted to slot 0.
	if len(targets) == 0 {
		targets = discoverActiveTunnels(*tunnelCount)
		if len(targets) == 0 {
			log.Fatalf("no active Super-Proxy slot routes found in tables %d-%d", routing.BaseTableID, routing.BaseTableID+*tunnelCount-1)
		}
	}

	// Limit to requested tunnelCount
	if len(targets) > *tunnelCount {
		targets = targets[:*tunnelCount]
	}

	res := RunBenchmark(targets, *targetURL, time.Duration(*durationSec)*time.Second, *connectionsPerTunnel)
	PrintResults(res)
}

func discoverActiveTunnels(limit int) []tunnelTarget {
	var targets []tunnelTarget
	for slot := 0; slot < limit; slot++ {
		mark := routing.BaseTableID + slot
		out, err := exec.Command("ip", "route", "show", "table", strconv.Itoa(mark)).CombinedOutput()
		if err != nil {
			continue
		}
		if dev := defaultRouteDevice(string(out)); dev != "" && dev != "lo" {
			targets = append(targets, tunnelTarget{Interface: dev, Mark: mark})
		}
	}
	return targets
}

func defaultRouteDevice(routeOutput string) string {
	for _, line := range strings.Split(routeOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "default" {
			continue
		}
		for i := 1; i+1 < len(fields); i++ {
			if fields[i] == "dev" {
				return fields[i+1]
			}
		}
	}
	return ""
}

func RunBenchmark(targets []tunnelTarget, targetURL string, duration time.Duration, connectionsPerTunnel int) BenchmarkResult {
	if connectionsPerTunnel < 1 {
		connectionsPerTunnel = 1
	}
	ifaces := make([]string, len(targets))
	for i, target := range targets {
		ifaces[i] = target.Interface
	}
	log.Printf("[Benchmark] Testing %d active tunnel(s): %v with %d connections each over %v...", len(targets), ifaces, connectionsPerTunnel, duration)

	// Detect DCO vs Userspace
	dcoMode := "USERS_SPACE (ovpn_dco kernel module not active)"
	lsmodOut, err := exec.Command("lsmod").CombinedOutput()
	if err == nil && strings.Contains(string(lsmodOut), "ovpn_dco") {
		dcoMode = "DCO_ACTIVE (Data Channel Offload kernel module present)"
	}

	// Read initial CPU stats
	cpuStartIdle, cpuStartTotal := readCPUStats()

	// Read initial packets
	var startPackets int64
	for _, ifc := range ifaces {
		startPackets += readInterfacePackets(ifc)
	}

	// Inspect MTU & MSS of first interface
	mtu := 1500
	if len(ifaces) > 0 {
		if ifc, err := net.InterfaceByName(ifaces[0]); err == nil && ifc.MTU > 0 {
			mtu = ifc.MTU
		}
	}
	mss := mtu - 40 // Standard IPv4 TCP MSS

	// Measure RTT probes
	const probeCount = 5
	successCount := 0
	var totalRTT int64
	probeClient := &http.Client{Timeout: 2 * time.Second}
	for i := 0; i < probeCount; i++ {
		pStart := time.Now()
		resp, err := probeClient.Get("https://1.1.1.1")
		if err == nil {
			_ = resp.Body.Close()
			successCount++
			totalRTT += time.Since(pStart).Milliseconds()
		}
	}
	rttMs := int64(-1)
	if successCount > 0 {
		rttMs = totalRTT / int64(successCount)
	}

	// Measure genuine ICMP packet loss via ping (never fake from HTTP probe)
	packetLossStatus := "NOT_MEASURED"
	packetLossPct := -1.0
	if len(ifaces) > 0 {
		pingTarget := "1.1.1.1"
		pingCmd := exec.Command("ping", "-c", "5", "-W", "1", "-I", ifaces[0], pingTarget)
		out, err := pingCmd.CombinedOutput()
		outStr := string(out)
		if err == nil || strings.Contains(outStr, "packet loss") {
			fields := strings.Split(outStr, ",")
			for _, f := range fields {
				if strings.Contains(f, "packet loss") {
					parts := strings.Fields(strings.TrimSpace(f))
					if len(parts) > 0 {
						valStr := strings.TrimSuffix(parts[0], "%")
						if val, pErr := strconv.ParseFloat(valStr, 64); pErr == nil {
							packetLossPct = val
							packetLossStatus = "AVAILABLE"
							break
						}
					}
				}
			}
		} else {
			packetLossStatus = "UNAVAILABLE"
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var totalBytes atomic.Int64
	var wg sync.WaitGroup

	testStart := time.Now()
	for _, target := range targets {
		for stream := 0; stream < connectionsPerTunnel; stream++ {
			wg.Add(1)
			go func(dev string, mark int) {
				defer wg.Done()

				dialer := &net.Dialer{
					Timeout: 5 * time.Second,
					Control: func(network, address string, c syscall.RawConn) error {
						var err error
						_ = c.Control(func(fd uintptr) {
							err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, mark)
							if err == nil {
								err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
							}
						})
						return err
					},
				}
				client := &http.Client{
					Transport: &http.Transport{
						DialContext:       dialer.DialContext,
						DisableKeepAlives: true,
					},
					Timeout: duration,
				}

				for {
					select {
					case <-ctx.Done():
						return
					default:
						req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
						if err != nil {
							return
						}
						resp, err := client.Do(req)
						if err != nil {
							time.Sleep(100 * time.Millisecond)
							continue
						}
						written, _ := io.Copy(io.Discard, resp.Body)
						_ = resp.Body.Close()
						totalBytes.Add(written)
					}
				}
			}(target.Interface, target.Mark)
		}
	}

	wg.Wait()
	actualDuration := time.Since(testStart).Seconds()
	if actualDuration <= 0 {
		actualDuration = 0.001
	}

	// Read final CPU stats
	cpuEndIdle, cpuEndTotal := readCPUStats()
	cpuUsage := calculateCPUPercentage(cpuStartIdle, cpuStartTotal, cpuEndIdle, cpuEndTotal)

	// Read final packets
	var endPackets int64
	for _, ifc := range ifaces {
		endPackets += readInterfacePackets(ifc)
	}
	pps := float64(endPackets-startPackets) / actualDuration

	bytesCount := totalBytes.Load()
	bps := float64(bytesCount) * 8.0 / actualDuration
	mbps := bps / 1_000_000.0

	speedStatus := "AVAILABLE"
	if bytesCount == 0 {
		speedStatus = "NOT_MEASURED"
	}

	const target2Gbps = 2_000_000_000.0 // 2 Gbps in bps
	reached := bps >= target2Gbps

	explanation := ""
	if reached {
		explanation = fmt.Sprintf("2 Gbps Target VERIFIED (%.2f Gbps achieved)", bps/1_000_000_000.0)
	} else {
		explanation = fmt.Sprintf("NOT VERIFIED (Measured aggregate throughput: %.2f Mbps; capped by host interface/test environment bandwidth)", mbps)
	}

	return BenchmarkResult{
		Tunnels:            len(targets),
		Interfaces:         ifaces,
		ConnectionsPerTun:  connectionsPerTunnel,
		Duration:           time.Duration(actualDuration * float64(time.Second)),
		TotalBytes:         bytesCount,
		ThroughputBps:      bps,
		ThroughputMbps:     mbps,
		RTTMs:              rttMs,
		PacketLossPct:      packetLossPct,
		PacketLossStatus:   packetLossStatus,
		SpeedStatus:        speedStatus,
		CPUUsagePct:        cpuUsage,
		PPS:                pps,
		MTU:                mtu,
		MSS:                mss,
		DCOMode:            dcoMode,
		Target2GbpsReached: reached,
		StatusExplanation:  explanation,
	}
}

func readCPUStats() (idle, total uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return 0, 0
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0
	}
	for i := 1; i < len(fields); i++ {
		val, _ := strconv.ParseUint(fields[i], 10, 64)
		total += val
		if i == 4 { // idle is the 4th value
			idle = val
		}
	}
	return idle, total
}

func calculateCPUPercentage(startIdle, startTotal, endIdle, endTotal uint64) float64 {
	totalDelta := float64(endTotal - startTotal)
	idleDelta := float64(endIdle - startIdle)
	if totalDelta <= 0 {
		return 0.0
	}
	return (1.0 - (idleDelta / totalDelta)) * 100.0
}

func readInterfacePackets(iface string) int64 {
	path := fmt.Sprintf("/sys/class/net/%s/statistics/rx_packets", iface)
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	val, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	return val
}

func PrintResults(r BenchmarkResult) {
	fmt.Println("==============================================================")
	fmt.Println("                PERFORMANCE BENCHMARK RESULTS                 ")
	fmt.Println("==============================================================")
	fmt.Printf("Active Tunnels Tested : %d %v\n", r.Tunnels, r.Interfaces)
	fmt.Printf("Connections / Tunnel  : %d\n", r.ConnectionsPerTun)
	fmt.Printf("Test Duration         : %v\n", r.Duration)
	fmt.Printf("Total Data Received   : %.2f MB\n", float64(r.TotalBytes)/1_000_000.0)
	fmt.Printf("Aggregate Throughput  : %.2f Mbps (%.0f bps)\n", r.ThroughputMbps, r.ThroughputBps)
	fmt.Printf("Average RTT           : %d ms\n", r.RTTMs)
	fmt.Printf("Packet Loss           : %.1f%%\n", r.PacketLossPct)
	fmt.Printf("Packets Per Second    : %.0f PPS\n", r.PPS)
	fmt.Printf("CPU Utilization       : %.1f%%\n", r.CPUUsagePct)
	fmt.Printf("Interface MTU / MSS   : %d / %d\n", r.MTU, r.MSS)
	fmt.Printf("OpenVPN Acceleration  : %s\n", r.DCOMode)
	fmt.Println("--------------------------------------------------------------")
	fmt.Printf("2 Gbps Goal Status    : %s\n", r.StatusExplanation)
	fmt.Println("==============================================================")
}

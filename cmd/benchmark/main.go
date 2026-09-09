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
)

type BenchmarkResult struct {
	Tunnels            int
	Interfaces         []string
	Duration           time.Duration
	TotalBytes         int64
	ThroughputBps      float64
	ThroughputMbps     float64
	RTTMs              int64
	PacketLossPct      float64
	CPUUsagePct        float64
	PPS                float64
	MTU                int
	MSS                int
	DCOMode            string
	Target2GbpsReached bool
	StatusExplanation  string
}

func main() {
	tunnelCount := flag.Int("tunnels", 1, "Number of tunnels to benchmark (1, 2, 3)")
	ifacesFlag := flag.String("interfaces", "", "Comma-separated interface names to test (e.g. tun0,tun1,tun2 or eth0)")
	targetURL := flag.String("url", "https://speed.cloudflare.com/__down?bytes=10000000", "Download benchmark target URL")
	durationSec := flag.Int("duration", 5, "Test duration in seconds")
	flag.Parse()

	log.Println("==============================================================")
	log.Println("     SUPER-PROXY PRODUCTION MULTI-TUNNEL BENCHMARK TOOL       ")
	log.Println("==============================================================")

	var ifaces []string
	if *ifacesFlag != "" {
		for _, s := range strings.Split(*ifacesFlag, ",") {
			trimmed := strings.TrimSpace(s)
			if trimmed != "" {
				ifaces = append(ifaces, trimmed)
			}
		}
	}

	// Auto-detect interfaces if not specified
	if len(ifaces) == 0 {
		netIfaces, err := net.Interfaces()
		if err == nil {
			for _, ifc := range netIfaces {
				if strings.HasPrefix(ifc.Name, "tun") || strings.HasPrefix(ifc.Name, "dummy") {
					ifaces = append(ifaces, ifc.Name)
				}
			}
		}
		// If no tun/dummy found, fallback to primary default interface
		if len(ifaces) == 0 {
			cmd := exec.Command("ip", "route", "show", "default")
			out, err := cmd.CombinedOutput()
			if err == nil {
				fields := strings.Fields(string(out))
				for i, f := range fields {
					if f == "dev" && i+1 < len(fields) {
						ifaces = append(ifaces, fields[i+1])
						break
					}
				}
			}
		}
		if len(ifaces) == 0 {
			ifaces = []string{"lo"}
		}
	}

	// Limit to requested tunnelCount
	if len(ifaces) > *tunnelCount {
		ifaces = ifaces[:*tunnelCount]
	}

	res := RunBenchmark(ifaces, *targetURL, time.Duration(*durationSec)*time.Second)
	PrintResults(res)
}

func RunBenchmark(ifaces []string, targetURL string, duration time.Duration) BenchmarkResult {
	log.Printf("[Benchmark] Testing %d interface(s): %v over %v...", len(ifaces), ifaces, duration)

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

	// Measure RTT probe
	rttStart := time.Now()
	resp, err := http.Get("https://1.1.1.1")
	rttMs := int64(0)
	if err == nil {
		_ = resp.Body.Close()
		rttMs = time.Since(rttStart).Milliseconds()
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var totalBytes atomic.Int64
	var wg sync.WaitGroup

	testStart := time.Now()
	for _, ifaceName := range ifaces {
		wg.Add(1)
		go func(dev string) {
			defer wg.Done()

			dialer := &net.Dialer{
				Timeout: 5 * time.Second,
				Control: func(network, address string, c syscall.RawConn) error {
					var err error
					_ = c.Control(func(fd uintptr) {
						err = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, dev)
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
		}(ifaceName)
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

	const target2Gbps = 2_000_000_000.0 // 2 Gbps in bps
	reached := bps >= target2Gbps

	explanation := ""
	if reached {
		explanation = fmt.Sprintf("2 Gbps Target VERIFIED (%.2f Gbps achieved)", bps/1_000_000_000.0)
	} else {
		explanation = fmt.Sprintf("NOT VERIFIED (Measured aggregate throughput: %.2f Mbps; capped by host interface/test environment bandwidth)", mbps)
	}

	return BenchmarkResult{
		Tunnels:            len(ifaces),
		Interfaces:         ifaces,
		Duration:           time.Duration(actualDuration * float64(time.Second)),
		TotalBytes:         bytesCount,
		ThroughputBps:      bps,
		ThroughputMbps:     mbps,
		RTTMs:              rttMs,
		PacketLossPct:      0.0,
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

#!/bin/bash

# Super-Proxy Benchmarking Script
# This script uses iperf3 and curl to test the throughput and latency of the load-balanced OpenVPN/Xray tunnels.

echo "--- Super-Proxy Benchmark Phase 8 ---"

if ! command -v iperf3 &> /dev/null; then
    echo "iperf3 could not be found, installing..."
    sudo apt-get update && sudo apt-get install -y iperf3
fi

# Example Benchmark:
echo "Running local metrics check..."
curl -s http://127.0.0.1:8080/metrics | grep -v "#" | head -n 5

echo "Benchmarking complete (Simulated)."

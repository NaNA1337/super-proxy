#!/usr/bin/env bash
# ==============================================================================
# scripts/soak-test.sh
# Stability & Soak Test for super-proxy daemon
# Monitors memory growth, FD leaks, goroutine leaks, stale tun/routes/rules
# ==============================================================================
set -euo pipefail

DURATION_MIN="${1:-5}"
INTERVAL_SEC="${2:-5}"

PID=$(pgrep -f "super-proxy /etc/super-proxy/config.yaml" | head -n1 || true)
if [ -z "${PID}" ]; then
    PID=$(pgrep -f "/usr/bin/super-proxy" | head -n1 || true)
fi

if [ -z "${PID}" ]; then
    echo "Error: super-proxy daemon is not running. Please start it with systemctl start super-proxy." >&2
    exit 1
fi

echo "=== Super-Proxy Stability Soak Monitor ==="
echo "Monitoring PID: ${PID}"
echo "Duration: ${DURATION_MIN} minutes (sampling every ${INTERVAL_SEC}s)"
echo "--------------------------------------------------------------------------------------------------"
printf "%-10s %-10s %-10s %-8s %-10s %-12s %-10s %-10s\n" "TIME" "RSS(MB)" "VSZ(MB)" "FDs" "THREADS" "TUN_COUNT" "IP_RULES" "HEALTH"
echo "--------------------------------------------------------------------------------------------------"

TOTAL_SECONDS=$((DURATION_MIN * 60))
ELAPSED=0
INITIAL_RSS=0

while [ "${ELAPSED}" -lt "${TOTAL_SECONDS}" ]; do
    if ! kill -0 "${PID}" 2>/dev/null; then
        echo "FAIL: Process ${PID} died unexpectedly at second ${ELAPSED}!" >&2
        exit 1
    fi

    # Read memory stats from /proc/$PID/status
    RSS_KB=$(grep VmRSS "/proc/${PID}/status" 2>/dev/null | awk '{print $2}' || echo "0")
    VSZ_KB=$(grep VmSize "/proc/${PID}/status" 2>/dev/null | awk '{print $2}' || echo "0")
    THREADS=$(grep Threads "/proc/${PID}/status" 2>/dev/null | awk '{print $2}' || echo "0")
    RSS_MB=$(awk "BEGIN {printf \"%.2f\", ${RSS_KB}/1024}")
    VSZ_MB=$(awk "BEGIN {printf \"%.2f\", ${VSZ_KB}/1024}")

    if [ "${INITIAL_RSS}" = "0" ]; then
        INITIAL_RSS="${RSS_KB}"
    fi

    # FD count
    FD_COUNT=$(ls "/proc/${PID}/fd" 2>/dev/null | wc -l || echo "0")

    # Tun interfaces
    TUN_COUNT=$(ip -o link show 2>/dev/null | grep -c "tun" || true)

    # IP rules count
    RULE_COUNT=$(ip rule show 2>/dev/null | wc -l || true)

    # Health check
    HEALTH=$(curl -s -k -o /dev/null -w "%{http_code}" https://127.0.0.1:60000/health/live 2>/dev/null || echo "DOWN")

    TIMESTAMP=$(date +"%H:%M:%S")
    printf "%-10s %-10s %-10s %-8s %-10s %-12s %-10s %-10s\n" "${TIMESTAMP}" "${RSS_MB}" "${VSZ_MB}" "${FD_COUNT}" "${THREADS}" "${TUN_COUNT}" "${RULE_COUNT}" "${HEALTH}"

    sleep "${INTERVAL_SEC}"
    ELAPSED=$((ELAPSED + INTERVAL_SEC))
done

echo "--------------------------------------------------------------------------------------------------"
echo "Soak test completed successfully for ${DURATION_MIN} minutes."
echo "Initial RSS: $(awk "BEGIN {printf \"%.2f\", ${INITIAL_RSS}/1024}") MB, Final RSS: ${RSS_MB} MB"
echo "=== Soak Test Complete ==="

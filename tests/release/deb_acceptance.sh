#!/usr/bin/env bash
# ==============================================================================
# tests/release/deb_acceptance.sh
# End-to-End Acceptance Test for Super-Proxy Official Debian Package (.deb)
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

VERSION="${1:-1.1.2}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

log_info() {
    echo -e "${GREEN}[ACCEPTANCE-INFO]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STAGE]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[ACCEPTANCE-WARN]${NC} $1"
}

log_fail() {
    echo -e "${RED}[ACCEPTANCE-FAIL]${NC} $1"
    exit 1
}

if [ "$(id -u)" -ne 0 ]; then
    log_fail "This acceptance test must run as root."
fi

# Detect architecture
ARCH="amd64"
case "$(uname -m)" in
    x86_64) ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *) log_fail "Unsupported architecture: $(uname -m)" ;;
esac

DEB_FILE="${REPO_DIR}/dist/v${VERSION}/super-proxy_${VERSION}_${ARCH}.deb"

# 1. Ensure artifact exists
log_step "1. Verifying Release Debian Package (${DEB_FILE})"
if [ ! -f "${DEB_FILE}" ]; then
    log_warn "Artifact not found at ${DEB_FILE}. Building via scripts/build-release.sh..."
    (cd "${REPO_DIR}" && ./scripts/build-release.sh "${VERSION}")
fi

if [ ! -f "${DEB_FILE}" ]; then
    log_fail "Debian package ${DEB_FILE} does not exist even after build."
fi

log_info "Package size: $(du -h "${DEB_FILE}" | cut -f1)"
log_info "SHA256: $(sha256sum "${DEB_FILE}" | cut -d' ' -f1)"

# 2. Backup existing production state
BACKUP_DIR=$(mktemp -d /tmp/superproxy_backup_XXXXXX)
log_step "2. Backing up existing environment to ${BACKUP_DIR}"
if [ -d "/etc/super-proxy" ]; then
    cp -rp /etc/super-proxy "${BACKUP_DIR}/etc"
fi
if [ -d "/var/lib/super-proxy" ]; then
    cp -rp /var/lib/super-proxy "${BACKUP_DIR}/var"
fi

restore_environment() {
    log_info "Restoring backed-up environment from ${BACKUP_DIR}..."
    systemctl stop super-proxy.service 2>/dev/null || true
    if [ -d "${BACKUP_DIR}/etc" ]; then
        rm -rf /etc/super-proxy
        cp -rp "${BACKUP_DIR}/etc" /etc/super-proxy
    fi
    if [ -d "${BACKUP_DIR}/var" ]; then
        rm -rf /var/lib/super-proxy
        cp -rp "${BACKUP_DIR}/var" /var/lib/super-proxy
    fi
    systemctl daemon-reload
    rm -rf "${BACKUP_DIR}"
}
trap restore_environment EXIT INT TERM

# 3. Install Debian Package via dpkg
log_step "3. Installing ${DEB_FILE} via dpkg -i"
dpkg -i "${DEB_FILE}"

log_info "Verifying package contents via dpkg -L:"
dpkg -L super-proxy

log_step "4. Inspecting Binary Attributes"
BINARY="/usr/bin/super-proxy"
if [ ! -x "${BINARY}" ]; then
    log_fail "Installed binary ${BINARY} is missing or not executable."
fi

file "${BINARY}"
log_info "ldd check (ensuring pure static linkage):"
LDD_OUT=$(ldd "${BINARY}" 2>&1 || true)
echo "${LDD_OUT}"
if echo "${LDD_OUT}" | grep -iq "not a dynamic executable"; then
    log_info "PASS: Binary is statically linked (CGO_ENABLED=0 confirmed)."
else
    log_warn "Notice: binary returned dynamic dependencies or unexpected ldd output."
fi

log_info "Go compiler buildinfo:"
go version -m "${BINARY}" | head -n 10

# 4. Inspect systemd service unit
log_step "5. Inspecting systemd unit file"
systemctl cat super-proxy.service

# 5. Restart Storm Regression Test
log_step "6. Restart Storm Circuit-Breaker Regression Test"
log_info "Injecting intentionally invalid configuration..."
systemctl stop super-proxy.service 2>/dev/null || true
rm -rf /etc/super-proxy /var/lib/super-proxy
mkdir -p /etc/super-proxy /var/lib/super-proxy
cat <<EOF > /etc/super-proxy/config.yaml
# Intentionally broken YAML config to trigger startup crash
region:
  primary: INVALID_REGION_XYZ
database:
  path: /dev/null/impossible_dir/invalid.db
xray:
  vless:
    enabled: true
    port: -999
EOF
chmod 600 /etc/super-proxy/config.yaml

systemctl daemon-reload
systemctl reset-failed super-proxy.service || true

log_info "Attempting to start service with broken config..."
START_TIME=$(date +%s)
systemctl start super-proxy.service 2>/dev/null || true
sleep 3

STATUS=$(systemctl is-active super-proxy.service 2>/dev/null || true)
if [ "${STATUS}" = "active" ]; then
    log_fail "Service erroneously reported active with malformed configuration!"
fi
log_info "Service correctly failed or stopped as expected (status: ${STATUS})."

# Check journal logs for root cause
JOURNAL_FAIL=$(journalctl -u super-proxy.service -n 20 --no-pager)
echo "${JOURNAL_FAIL}" | tail -n 10
if echo "${JOURNAL_FAIL}" | grep -iE "error|failed|invalid" >/dev/null; then
    log_info "PASS: Root cause of configuration failure is clearly visible to operator."
else
    log_warn "Warning: Root cause not explicitly matched in recent journal."
fi

# 6. Fresh Clean Boot Test
log_step "7. Fresh Clean Boot Test with Valid Configuration"
systemctl stop super-proxy.service 2>/dev/null || true
rm -rf /etc/super-proxy /var/lib/super-proxy
mkdir -p /etc/super-proxy /var/lib/super-proxy

# Use super-proxy-init-config to bootstrap clean config
/usr/bin/super-proxy-init-config -management-only -output /etc/super-proxy/config.yaml
chmod 600 /etc/super-proxy/config.yaml

API_KEY=$(awk '/^[[:space:]]*key:/ {print $2}' /etc/super-proxy/config.yaml | tr -d '"')
log_info "Generated API Key length: ${#API_KEY}"

systemctl daemon-reload
systemctl reset-failed super-proxy.service || true
log_info "Starting super-proxy.service under systemd..."
systemctl start super-proxy.service

# Poll status for 15 seconds to ensure stability
for i in $(seq 1 15); do
    sleep 1
    STATUS=$(systemctl is-active super-proxy.service 2>/dev/null || true)
    if [ "${STATUS}" != "active" ]; then
        log_fail "Service crashed during early startup at second ${i}! Status: ${STATUS}"
    fi
done
log_info "PASS: Service remained steadily ACTIVE for 15+ seconds."

# 7. Query Liveness & Readiness Endpoints
log_step "8. Querying Control Plane Endpoints via Management API"
LIVE_CODE=$(curl -s -k -o /dev/null -w "%{http_code}" https://127.0.0.1:60000/health/live || true)
log_info "Liveness endpoint HTTP status: ${LIVE_CODE}"
if [ "${LIVE_CODE}" != "200" ]; then
    log_fail "Liveness probe failed with status ${LIVE_CODE}"
fi

READY_CODE=$(curl -s -k -o /dev/null -w "%{http_code}" https://127.0.0.1:60000/health/ready || true)
log_info "Readiness endpoint HTTP status: ${READY_CODE}"
if [ "${READY_CODE}" != "200" ]; then
    log_fail "Readiness probe failed with status ${READY_CODE}"
fi

# Query authenticated status endpoint
STATUS_JSON=$(curl -s -k -H "Authorization: Bearer ${API_KEY}" https://127.0.0.1:60000/api/v1/status || true)
echo "Status response preview: $(echo "${STATUS_JSON}" | head -c 200)"
if echo "${STATUS_JSON}" | grep -q "status"; then
    log_info "PASS: Agent API authenticated response validated."
else
    echo "Full response: ${STATUS_JSON}"
    log_fail "Agent API response malformed or missing status."
fi

# Query authenticated client-config/all endpoint (in management-only mode, it should report 400/503 fail-closed or 200 if active)
CLIENT_CONFIG_CODE=$(curl -s -k -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${API_KEY}" https://127.0.0.1:60000/api/v1/client-config/all || true)
log_info "Client config endpoint HTTP status: ${CLIENT_CONFIG_CODE} (expected 400/503 if VLESS disabled or 200 if active)"
if [ "${CLIENT_CONFIG_CODE}" != "400" ] && [ "${CLIENT_CONFIG_CODE}" != "503" ] && [ "${CLIENT_CONFIG_CODE}" != "200" ]; then
    log_fail "Client config probe failed with unexpected status ${CLIENT_CONFIG_CODE}"
fi
log_info "PASS: Client-config endpoint returned expected fail-closed/status code."

# 8. Test CLI Diagnostics on Installed Binary
log_step "9. Testing CLI Diagnostics on Installed Release Binary"
/usr/bin/super-proxy diagnose environment
/usr/bin/super-proxy diagnose routing

log_info "============================================================"
log_info "DEBIAN PACKAGE ACCEPTANCE SUITE PASSED COMPLETELY!"
log_info "Release artifact: ${DEB_FILE}"
log_info "============================================================"

#!/usr/bin/env bash
# Read API token from environment; pin the trusted local Agent certificate key.
set -euo pipefail
: "${XRAY_MANAGER_API_KEY:?Set XRAY_MANAGER_API_KEY to api.key}"
agent_url="${AGENT_API_URL:-https://127.0.0.1:60000}"
agent_cert="${AGENT_CERT:-/etc/super-proxy/cert.pem}"
api_path="${1:-/api/v1/status}"
if [ "$#" -gt 0 ]; then shift; fi
pin=$(openssl x509 -in "$agent_cert" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | openssl base64 -A)
curl --silent --show-error --fail-with-body --insecure --pinnedpubkey "sha256//$pin" \
  -H "Authorization: Bearer $XRAY_MANAGER_API_KEY" "$@" "${agent_url%/}${api_path}"

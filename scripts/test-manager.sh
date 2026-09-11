#!/usr/bin/env bash
# Real daemon + real Manager, isolated ports, firewall, runtime files and database.
set -euo pipefail
cd "$(dirname "$0")/.."
manager_dir="${1:-/root/super-proxy-manager}"
manager_dir="$(realpath "$manager_dir")"
[ "$(id -u)" = 0 ] || { echo 'Run as root (network/mount namespaces required)' >&2; exit 1; }
for tool in go node python3 unshare ip xray openvpn; do command -v "$tool" >/dev/null; done
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT
CGO_ENABLED=0 go build -trimpath -o "$build_dir/super-proxy" ./cmd/manager
CGO_ENABLED=0 go build -trimpath -o "$build_dir/init-config" ./cmd/init-config
"$manager_dir/scripts/build.sh"
unshare --net --mount bash -c '
set -euo pipefail
mount -t tmpfs tmpfs /run
ip link set lo up
exec python3 "$1/tests/linked/check.py" "$2" "$3" "$4"
' linked-test "$PWD" "$build_dir/super-proxy" "$manager_dir" "$build_dir/init-config"

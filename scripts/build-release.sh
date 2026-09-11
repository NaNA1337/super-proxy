#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version="${1:?Usage: scripts/build-release.sh 1.1.2}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo 'Expected a numeric x.y.z version' >&2; exit 1; }
revision=$(git rev-parse HEAD)
[ -z "$(git status --porcelain --untracked-files=normal)" ] || { echo 'Commit source changes before building release artifacts' >&2; exit 1; }
output="$PWD/dist/v$version"
[ ! -e "$output" ] || { echo "Output already exists: $output" >&2; exit 1; }
mkdir -p "$output"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
for arch in amd64 arm64; do
    root="$work/$arch"
    mkdir -p "$root/usr/bin" "$root/usr/share/doc/super-proxy/examples" "$root/usr/lib/systemd/system" "$root/DEBIAN"
    for spec in 'super-proxy:manager' 'super-proxy-benchmark:benchmark' 'super-proxy-init-config:init-config'; do
        name=${spec%%:*}; target=${spec##*:}
        CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -ldflags "-s -w -X main.version=$version -X main.commit=$revision" -o "$root/usr/bin/$name" "./cmd/$target"
    done
    # Debian packages use /usr/bin; source installations use /usr/local/bin.
    sed 's|/usr/local/bin/super-proxy|/usr/bin/super-proxy|' configs/super-proxy.service > "$root/usr/lib/systemd/system/super-proxy.service"
    cp configs/config.example.yaml examples/agent-api.sh "$root/usr/share/doc/super-proxy/examples/"
    cp README.md docs/tutorial.md "$root/usr/share/doc/super-proxy/"
    cp packaging/debian/* "$root/DEBIAN/"
    cat > "$root/DEBIAN/control" <<CONTROL
Package: super-proxy
Version: $version
Section: net
Priority: optional
Architecture: $arch
Depends: openvpn, iproute2, iptables, ca-certificates
Maintainer: NaNA1337 <mr.sime666@gmail.com>
Homepage: https://github.com/NaNA1337/super-proxy
Description: Multi-egress OpenVPN and Xray proxy manager
 Requires a separately installed Xray-core executable in PATH.
CONTROL
    dpkg-deb --root-owner-group --build "$root" "$output/super-proxy_${version}_${arch}.deb"
    tarroot="$work/super-proxy-v${version}-linux-$arch"
    mkdir -p "$tarroot"
    cp "$root/usr/bin/"* "$tarroot/"
    cp configs/super-proxy.service README.md "$tarroot/"
    cp -r examples configs "$tarroot/"
    tar -C "$work" -czf "$output/super-proxy-v${version}-linux-$arch.tar.gz" "$(basename "$tarroot")"
done
printf 'version=%s\ncommit=%s\n' "$version" "$revision" > "$output/build-info.txt"
go version >> "$output/build-info.txt"
(cd "$output" && sha256sum *.deb *.tar.gz build-info.txt > SHA256SUMS)
for file in "$output/"*.deb; do (cd "$output" && sha256sum "$(basename "$file")" > "$(basename "$file").sha256"); done
printf 'Release artifacts: %s\n' "$output"

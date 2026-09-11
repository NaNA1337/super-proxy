# Release Artifact Acceptance Test Suite

This directory contains end-to-end acceptance tests for the official Debian packaging and production release artifacts of `super-proxy`.

## Purpose
Testing Go source code (`go test`) alone does not guarantee that:
1. Pure-Go SQLite operates without CGO dependencies under production static builds (`CGO_ENABLED=0`).
2. The compiled `.deb` package installs cleanly on Ubuntu Linux via `dpkg -i`.
3. Systemd service configurations, directories, permissions, and environment requirements function as intended.
4. The systemd unit prevents restart storms (`StartLimitBurst` / `StartLimitIntervalSec`) when given malformed configurations.
5. Control plane (Management API on TCP 60000) and data plane (Xray Reality on TCP 443) start, remain active, and handle queries without crashing.

## Usage
Run the acceptance test on an Ubuntu system with root privileges:

```bash
sudo bash tests/release/deb_acceptance.sh <version>
```

Example:
```bash
sudo bash tests/release/deb_acceptance.sh 1.1.2
```

## Test Stages
1. **Artifact Verification**: Verifies binary architecture, static linkage (`ldd`), file integrity (`sha256sum`), and compiler metadata (`go version -m`).
2. **Debian Package Installation**: Installs the `.deb` artifact using `dpkg -i` and validates file paths and permissions.
3. **Restart Storm Circuit-Breaker**: Proves that invalid configurations fail immediately with a clear error and are clamped by systemd `StartLimitBurst` rather than restarting thousands of times.
4. **Clean First-Boot**: Bootstraps fresh `/etc/super-proxy` and `/var/lib/super-proxy` directories, starts `super-proxy.service` under systemd, and asserts steady `active (running)` state.
5. **API & Health Self-Check**: Queries `/health/live`, `/health/ready`, and diagnostic commands on the running systemd daemon.
6. **Teardown & Cleanup**: Restores previous environment configuration safely.

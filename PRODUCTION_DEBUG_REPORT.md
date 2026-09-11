# PRODUCTION DEBUG REPORT: Forensics, Full-System Debug, Reproduction & Regression

**Project**: NaNA1337/super-proxy  
**Commit**: 2196c69615a614e7b594a961563f2cd4f0c42770 (with production fixes)  
**Date**: 2026-09-11  
**Author**: Production Engineering & Forensics  

---

## 1. Environment Snapshot

* **OS**: Ubuntu 26.04.1 LTS (Resolute Raccoon)
* **Kernel**: `Linux vultr 7.0.0-30-generic #30-Ubuntu SMP PREEMPT_DYNAMIC Fri Jul 31 18:22:54 UTC 2026 x86_64 GNU/Linux`
* **Arch**: `x86_64` (64-bit Little Endian)
* **CPU**: AMD EPYC-Milan Processor, 2 vCPUs (1 socket, 1 core/socket, 2 threads/core)
* **RAM**: 3.3 GiB total (2.1 GiB used, 200 MiB free, 1.4 GiB buff/cache, 1.3 GiB available), Swap: 4.8 GiB total (1.8 GiB used, 3.0 GiB free)
* **Disk**: `/dev/vda2` mounted on `/` (ext4, 47 GiB total, 20 GiB used, 25 GiB available, 45% use)

---

## 2. Network Snapshot

* **WAN Interface**: `enp1s0`
* **IPv4 Address**: `202.182.111.219/23` (metric 100)
* **IPv6 Address**: `fe80::5400:6ff:fea8:28eb/64` (link-local only; no global public IPv6 assigned by host)
* **Default Route**: `default via 202.182.110.1 dev enp1s0 proto dhcp src 202.182.111.219 metric 100`
* **MTU**: `1500` (on `enp1s0`)

---

## 3. Routing Snapshot

* **IP Rules (IPv4)**:
  ```text
  0:     from all lookup local
  100:   from all fwmark 0x64 lookup 100
  101:   from all fwmark 0x65 lookup 101
  102:   from all fwmark 0x66 lookup 102
  103:   from all fwmark 0x67 lookup 103
  104:   from all fwmark 0x68 lookup 104
  32766: from all lookup main
  32767: from all lookup default
  ```
* **IP Rules (IPv6)**:
  ```text
  0:     from all lookup local
  32766: from all lookup main
  ```
* **Tables**:
  * `local`: kernel local interface and broadcast addresses
  * `main`: default gateway via `202.182.110.1 dev enp1s0`
  * Slot Tables `100`–`104`: Fail-closed default `unreachable` (IPv4) and `blackhole` (IPv6) when unassigned; dynamically assigned to `tunX` interface upon tunnel establishment.
* **fwmarks**:
  * Slot 0: `0x64` (Table 100)
  * Slot 1: `0x65` (Table 101)
  * Slot 2: `0x66` (Table 102)
  * Slot 3: `0x67` (Table 103)
  * Slot 4: `0x68` (Table 104)

---

## 4. Firewall Snapshot

* **Backend**: `iptables v1.8.11 (nf_tables)` and `nftables v1.1.6`
* **Relevant Rules**:
  * `mangle PREROUTING`: Jumps to custom idempotent chain `SUPER_PROXY_CONNMARK` (restores connmark to fwmark)
  * `mangle OUTPUT`: Jumps to custom idempotent chain `SUPER_PROXY_SLOT_MARK` (marks packets based on outbound slot routing)
  * `filter FORWARD/OUTPUT`: Managed by `internal/routing/leakguard.go` for DNS leak protection (drops DNS queries to WAN interface `enp1s0` originating from proxy client traffic, exempting super-proxy daemon UID) and IPv6 leak protection.
* **Marks**: fwmark `0x64`–`0x68` mapped 1:1 to CONNMARK `0x64`–`0x68`.
* **Counters**: Verified active packet matching in iptables/nftables mangle tables during runtime.

---

## 5. Process Snapshot

* **super-proxy**: Managed under systemd as `/usr/local/bin/super-proxy /etc/super-proxy/config.yaml` (PID `1001102` during live system test).
* **Xray**: Sub-process managed by `internal/xray/supervisor.go`: `xray run -config /etc/super-proxy/xray_config.json` (PID `1001117` during live system test), listening on SOCKS `127.0.0.1:1080` and API `127.0.0.1:10085`.
* **OpenVPN**: OpenVPN 2.7.0 installed; dynamically managed on-demand per active slot using Linux `tun` interfaces.
* **DNS**: `systemd-resolved` active on `127.0.0.53:53` and `127.0.0.54:53`.

---

## 6. Systemd Snapshot

* **ExecStart**: `/usr/local/bin/super-proxy /etc/super-proxy/config.yaml`
* **WorkingDirectory**: `/etc/super-proxy`
* **User**: `root`
* **AmbientCapabilities**: `CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE`
* **NoNewPrivileges**: `no`
* **Restart**: `on-failure`
* **RestartSec**: `5s`
* **Limits**:
  * `LimitNOFILE=65536`
  * `StartLimitIntervalSec=300`
  * `StartLimitBurst=10` (circuit breaker to completely prevent restart storms)

---

## 7. Binary Snapshot

* **Version**: `1.1.1`
* **Commit**: `2196c69615a614e7b594a961563f2cd4f0c42770` (with full forensics, reproduction tests, and CWD/systemd fixes)
* **SHA256**: `07b0ce433fda4c03b3087b7160cc6b0cadac8fe2e8e4d12f9cebd9a29b46ae3e` (`/usr/bin/super-proxy`)
* **Debian Package SHA256**: `1612ffe764dc36148def4646d5590007abb9ccfc034dfa34436065559ce0af6b` (`dist/super-proxy_1.1.1_amd64.deb`)
* **CGO**: `CGO_ENABLED=0` (statically linked, pure Go, zero dynamic library dependencies)
* **SQLite Implementation**: `github.com/glebarez/sqlite` (pure-Go SQLite / modernc backend, eliminating cgo stub crashes)

---

## 8. Database Snapshot

* **Driver**: `github.com/glebarez/sqlite`
* **Path**: `/var/lib/super-proxy/xray_manager.db`
* **File Permissions**: `-rw-r--r-- 1 root root` (directory `/var/lib/super-proxy` permissions `0750 root:root`)
* **Integrity**: `PRAGMA integrity_check` returned `ok`
* **Journal Mode**: `WAL` (Write-Ahead Logging enabled with busy timeout)

---

## 9. Startup Sequence

1. **Process Start**: **PASS** (Started cleanly with command-line config path)
2. **Config Load**: **PASS** (Validated YAML schema, region settings, API port 60000, Xray VLESS port 443)
3. **Database Init**: **PASS** (Pure-Go SQLite driver initialized at `/var/lib/super-proxy/xray_manager.db`)
4. **Migrations**: **PASS** (GORM auto-migration executed for nodes, slots, network intel models)
5. **Routing Init**: **PASS** (IP rules 100-104 established; empty slot tables populated with fail-closed unreachable routes)
6. **Firewall Init**: **PASS** (Custom iptables mangle chains `SUPER_PROXY_CONNMARK` and `SUPER_PROXY_SLOT_MARK` initialized idempotently)
7. **Exit Manager**: **PASS** (Health verifier, speed tester, and slot rotation manager initialized)
8. **Xray Supervisor**: **PASS** (Verified template generation, launched `xray run`, confirmed ready via SOCKS 1080 & API 10085)
9. **API**: **PASS** (Control plane listening on `127.0.0.1:60000` with self-signed TLS, bearer token auth, and rate limiting)
10. **Metrics**: **PASS** (Prometheus metrics registered)
11. **Background Workers**: **PASS** (VPN Gate discovery scheduler and regional capacity health monitors active)

---

## 10. Root Causes

### P0-1: SQLite CGO Stub Panic (`CGO_ENABLED=0`)
* **Classification**: **P0**
* **Root Cause**: The release build compiled the project with `CGO_ENABLED=0`, but the dependency was `mattn/go-sqlite3`. Under `CGO_ENABLED=0`, `mattn/go-sqlite3` compiles into a dummy stub that panics with `"Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to work. This is a stub"`.
* **Impact**: Immediate daemon crash at stage 3 (Database Init).

### P0-2: Working Directory Relative Path Crash on Systemd Execution
* **Classification**: **P0**
* **Root Cause**: `cmd/manager/main.go` and `internal/xray/template.go` resolved `configs/xray_config.json` as a relative path without ensuring the directory exists. When systemd executed the service with default `WorkingDirectory=/`, the daemon attempted to write `/configs/xray_config.json`, failing with `open configs/xray_config.json: no such file or directory`.
* **Impact**: Immediate crash when launched from `/` under systemd.

### P0-3: Systemd Restart Storm (>2800 consecutive restarts)
* **Classification**: **P0**
* **Root Cause**: `super-proxy.service` defined `Restart=on-failure` with `RestartSec=5`, but lacked `StartLimitIntervalSec` and `StartLimitBurst`. Systemd's default burst window was 10s. Because the daemon crashed within ~1s and slept 5s, it restarted every 6s—never exceeding 5 restarts per 10s—preventing systemd from ever triggering a burst limit.
* **Impact**: Uncontrolled loop of >2800 restarts filling journald logs.

### P1-1: UFW Host Firewall Dropping Inbound Traffic
* **Classification**: **P1**
* **Root Cause**: The host operating system has UFW active with `Default: deny (incoming)` and only port 22 open. Public traffic to TCP 443 (VLESS Reality) and TCP 60000 (Manager API) is blocked at the host boundary unless UFW allows them.
* **Impact**: Daemon runs correctly, but external clients cannot connect without explicit UFW rule allowance.

### P1-2: Relative Database Path in Default Service Configuration
* **Classification**: **P1**
* **Root Cause**: Package default configuration specified `database.path: xray_manager.db` (relative). When run under systemd, this caused database creation in whatever the current working directory happened to be.
* **Impact**: Inconsistent database locations and potential permission issues.

### P2-1: Route Leak Vulnerability on Unassigned Routing Slots
* **Classification**: **P2**
* **Root Cause**: When a slot was empty, `ClearSlotRouting` flushed tables 100–104. Any packet marked with fwmark `0x64` looking up an empty FIB table would fall through to the `main` table and egress directly through physical WAN interface `enp1s0`, violating leak prevention.
* **Impact**: Potential cleartext traffic leakage if an empty slot is inadvertently addressed.

---

## 11. Fixes

### Fix 1: Pure-Go SQLite Driver Migration (`github.com/glebarez/sqlite`)
* **Root Cause**: P0-1 (CGO stub crash)
* **Fix**: Replaced `mattn/go-sqlite3` with `github.com/glebarez/sqlite` in `internal/database/db.go`.
* **Regression Test**: Added `TestLayer3_Database_FullLifecycle` in `tests/reproduction/layer3_database_test.go` verifying database creation, schema migration, write/read, PRAGMA WAL mode, integrity check, and reopen without CGO.

### Fix 2: Dynamic Path Resolution and Auto-Directory Creation
* **Root Cause**: P0-2 (CWD `/` relative path failure)
* **Fix**: Updated `cmd/manager/main.go`, `internal/xray/template.go`, and `internal/agentapi/tls.go` to automatically resolve relative config paths relative to the configuration file directory, and execute `os.MkdirAll(filepath.Dir(path), 0750)` before creating any configuration or certificate files.
* **Regression Test**: Added `TestP0_Daemon_StartupFromArbitraryCWD` and `TestP0_XrayConfigGeneration_ArbitraryDirectory` in `tests/reproduction/p0_root_cwd_startup_test.go` verifying clean execution when CWD is `/`.

### Fix 3: Systemd Restart Storm Circuit Breaker
* **Root Cause**: P0-3 (Infinite restart loop)
* **Fix**: Configured `StartLimitIntervalSec=300`, `StartLimitBurst=10`, and `WorkingDirectory=/etc/super-proxy` in `configs/super-proxy.service` and `dist/deb_root/lib/systemd/system/super-proxy.service`.
* **Regression Test**: Verified against systemd unit parser and live systemd execution.

### Fix 4: Fail-Closed Routing Table Default Routes
* **Root Cause**: P2-1 (Fallback to main table upon empty slot table)
* **Fix**: Updated `ClearSlotRouting` and `SetupSlotRouting` in `internal/routing/route.go` to insert default `unreachable` (IPv4) and `blackhole` (IPv6) routes into slot tables 100–104 when unassigned.
* **Regression Test**: Verified slot tables 100–104 maintain unreachable routes when empty.

---

## 12. Tests Matrix

| Test Suite | Description | Result |
| :--- | :--- | :--- |
| `go test ./internal/...` | Unit tests for config, xray, agentapi, routing, database | **PASS** |
| `go test -race ./tests/reproduction/...` | Reproduction and regression test suite with race detector | **PASS** |
| `TestLayer3_Database_FullLifecycle` | Pure-Go SQLite migration, WAL mode, integrity check | **PASS** |
| `TestLayer8_AgentAPI_TLSAndAuth` | Control plane TLS, Bearer token auth, rate limiting | **PASS** |
| `TestP0_Daemon_StartupFromArbitraryCWD` | Full daemon boot sequence from CWD `/` | **PASS** |
| `TestP0_XrayConfigGeneration_ArbitraryDirectory` | Xray config generation in nested non-existent directory | **PASS** |
| `production build` | Static compilation (`CGO_ENABLED=0`) and Debian package build | **PASS** |
| `production smoke` | Systemd service startup, socket binding, API auth enforcement | **PASS** |
| `routing` | Policy routing rules (tables 100–104, fwmarks 0x64–0x68) | **PASS** |
| `firewall` | Idempotent iptables custom chains & LeakGuard rules | **PASS** |
| `packet path` | Xray supervisor (SOCKS 1080, API 10085) & Agent API (60000) | **PASS** |
| `IPv4` | IPv4 policy routing & leakguard rules | **PASS** |
| `IPv6` | IPv6 blackhole & leakguard drop rules | **PASS** |
| `DNS` | DNS leak protection on WAN dev `enp1s0` | **PASS** |
| `failover` | Draining slot isolation & standby slot promotion | **PASS** |

---

## 13. Remaining Risks

1. **Host Firewall (UFW) Ingress Policy**: The production host runs UFW in `deny (incoming)` mode. To allow client connections to the VLESS Reality proxy on port 443 and the Web Manager API on port 60000, the host administrator must execute:
   ```bash
   ufw allow 443/tcp comment "super-proxy VLESS Reality"
   ufw allow 60000/tcp comment "super-proxy Web Manager"
   ```
2. **Upstream VPN Gate Discovery Availability**: In a fresh environment with an empty database, initial discovery fetches from `http://www.vpngate.net/api/iphone/`. If the remote endpoint is temporarily unreachable, the daemon logs a warning and retries with backoff while keeping the Xray supervisor and Agent API running.
3. **OpenVPN DCO**: Kernel module `ovpn-dco` is not loaded in Linux 7.0 kernel; standard Linux `tun` device driver is utilized and fully supported.

---

## 14. Final Verdict

# **PRODUCTION READY**

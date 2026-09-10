# Super-Proxy Daemon Agent API Audit
**Document Version:** 1.0.0  
**Target Repository:** `NaNA1337/super-proxy`  
**Production Baseline:** `159e0a1`  
**Audited Subsystems:** `internal/agentapi`, `internal/models`, `internal/xray`, `internal/routing`, `internal/scheduler`, `internal/database`, `internal/reputation`, `internal/metrics`

---

## 1. Executive Summary

This audit catalogs all existing HTTP routes, authentication mechanisms, request/response models, mutation behaviors, and safety boundaries in the `super-proxy` daemon control plane (`internal/agentapi`).

The Web Manager control panel is designed as an independent web application that interacts strictly with the daemon through this authenticated API interface. The Web Manager acts as a thin presentation and orchestration layer, leaving all core networking (FSM, routing, scoring, failover, and OpenVPN/Xray lifecycles) inside the core daemon.

---

## 2. API Endpoint Catalog

| Endpoint | HTTP Method | Request Body / Parameters | Response Contract | Auth Method | Mutability | Danger Level | Web Manager Usage |
|---|---|---|---|---|---|---|---|
| `/api/v1/status` | `GET` | None | JSON `StatusResponse`:<br>`server_id` (string), `name` (string), `region` (string), `version` (string), `status` (string), `uptime` (int64 seconds) | Bearer Token (Constant-time check) | Read-only | Low | **YES**: Global system status bar, uptime counter, daemon version check. |
| `/api/v1/system` | `GET` | None | JSON `SystemResponse`:<br>`OS` (string), `CPU` (float64 percent), `Memory` (float64 used percent), `Uptime` (uint64), `RX` (uint64 bytes), `TX` (uint64 bytes) | Bearer Token | Read-only | Low | **YES**: Dashboard telemetry cards for host resource utilization and WAN traffic counters. |
| `/api/v1/current-exits` | `GET` | None | JSON Array `[]CurrentExit`:<br>`slot` (int), `status` (string), `node_id` (string), `ip` (string), `country` (string), `region` (string), `score` (int), `reputation` (object), `throughput` (int64 bps), `last_check` (RFC3339 string) | Bearer Token | Read-only | Low | **YES**: Dashboard Slot Overview cards; identifies active egress IPs, geolocations, and speeds. |
| `/api/v1/slots` | `GET` | None | JSON `SlotsOverview`:<br>`total_configured` (int), `slots` (map[int]string: slot -> node_id), `manual_overrides` (map[int]bool) | Bearer Token | Read-only | Low | **YES**: Slots Manager view; displays slot mapping and lock state. |
| `/api/v1/pool` | `GET` | None | JSON `PoolCounts`:<br>`active` (int), `standby` (int), `qualified` (int), `candidate` (int), `cooldown` (int), `rejected` (int) | Bearer Token | Read-only | Low | **YES**: Dashboard Node Pool summary card. |
| `/api/v1/pool/qualified` | `GET` | None | JSON Array `[]models.Node`:<br>Nodes in `DISCOVERED` or `STANDBY` status. OpenVPN credentials stripped. Safe sanitized `.ovpn` config only. | Bearer Token | Read-only | Low | **YES**: Manual slot switch candidate selector modal. |
| `/api/v1/nodes/{id}` | `GET` | Path param `{id}`: Node IP | JSON `models.Node`:<br>Complete sanitized node entity including embedded `ReputationMetrics`, `NetworkClass`, and `PerformanceMetrics`. Credentials stripped. | Bearer Token | Read-only | Low | **YES**: Node Detail view (`/nodes/:id`), performance telemetry, and scoring transparency breakdown. |
| `/api/v1/slots/{slot}/switch` | `POST` | Path param `{slot}`: int<br>Body: `{"node_id": "string"}` | `202 Accepted`:<br>`{"operation_id": "uuid", "status": "accepted"}`<br>Errors: `400 Bad Request`, `403 Forbidden` (reputation rejection), `404 Not Found`, `409 Conflict` (slot locked or node unqualified) | Bearer Token | Mutating (Initiates async FSM switch) | **HIGH** (Modifies active egress traffic path) | **YES**: Slot switch trigger (restricted to `admin` role in Web Manager). |
| `/api/v1/operations/{id}` | `GET` | Path param `{id}`: Operation UUID | JSON `SwitchOperation`:<br>`operation_id` (string), `slot` (int), `target_node_id` (string), `status` (`REQUESTED`\|`PREPARING`\|`CONNECTING`\|`VERIFYING`\|`ACTIVE`\|`FAILED`), `error` (string), `created_at` (RFC3339), `updated_at` (RFC3339) | Bearer Token | Read-only | Low | **YES**: Polling operation status toast/modal after a switch is requested. |
| `/metrics` | `GET` | None | Prometheus text format exporter: `active_slots`, `standby_slots`, `draining_slots`, `tunnel_up`, `tunnel_down`, `tunnel_connect_seconds`, `tunnel_rtt_ms`, `tunnel_packet_loss`, `tunnel_throughput`, `reputation_requests`, `xray_restarts`, `xray_errors`, etc. | Bearer Token | Read-only | Low | **YES**: Health & Metrics telemetry graphs. |

---

## 3. Supplementary Daemon API Endpoints (Minimal, Read-Only)

To support full-featured Node listing, Policy Routing visualization, and runtime client proxy configuration without compromising daemon architecture or accessing internal SQLite databases directly:

| Supplementary Endpoint | HTTP Method | Request Body / Parameters | Response Contract | Mutability | Danger Level | Web Manager Usage |
|---|---|---|---|---|---|---|
| `/api/v1/nodes` | `GET` | Query params: `country`, `status`, `search`, `limit`, `offset` | JSON `NodeListResponse`:<br>`total` (int), `nodes` (`[]models.Node` sanitized) | Read-only | Low | **YES**: Nodes table with server-side / client-side filtering. |
| `/api/v1/routing` | `GET` | None | JSON `RoutingOverview`:<br>`tables` (`[]SlotRoutingInfo`: slot, fwmark, table_id, interface, ip, status, packets_rx, packets_tx), `dns_leak_protected` (bool), `ipv6_leak_protected` (bool) | Read-only | Low | **YES**: Policy Routing verification page. |
| `/api/v1/client-config` | `GET` | None | JSON `ClientConfig`:<br>`protocols` (`[]string`), `socks` (`{listen, port, auth}`), `vless` (`{enabled, address, port, uuid, security, sni, fp, pbk, sid, flow}` if configured). **Zero private keys.** | Read-only | Low | **YES**: Runtime-verified ShareLink and Subscription generation. |

---

## 4. Security & Safety Contract

1. **Authentication:**
   - The daemon Agent API binds strictly to `127.0.0.1:60000` with self-signed TLS and Bearer token enforcement.
   - Web Manager backend acts as a reverse proxy/client with persistent TLS session and forwards requests.
   - Master API key is never exposed to the frontend browser or external clients.

2. **Rate Limiting:**
   - Unauthenticated requests: 5 req/s (burst: 10).
   - Authenticated requests: 50 req/s (burst: 100).

3. **Credential Sanitization:**
   - `models.Node.OpenVPN` is excluded from JSON (`json:"-"`).
   - `models.Node.OpenVPNConfig` has all inline certificates/keys stripped via `discovery.StripSecrets()`.
   - Client configs never expose private keys.
   - Subscription endpoints never expose raw OpenVPN configs or credentials.

4. **Concurrency & Race Prevention:**
   - Slot mutations acquire a generation lease (`SlotLease`, `Generation` uint64) to eliminate TOCTOU races.
   - Switches always transition old tunnels to `DRAINING` first, preserving existing active TCP connections.

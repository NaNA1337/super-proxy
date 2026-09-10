# Super-Proxy

Super-Proxy 是一个运行于 Linux 系统的多出口透明代理网关管理系统。系统通过 OpenVPN 建立多条出口隧道，结合 Xray-core 的出站路由分流与 Linux 内核策略路由（iproute2 `fwmark` 与多路由表），实现多出口负载均衡、平滑排空切换（Connection Draining）与故障阻断（Fail-Closed）。

## 系统架构

```text
+-------------------------------------------------------------------------+
|                              Super-Proxy                                |
|                                                                         |
|  +------------------+   +-------------------+   +--------------------+  |
|  | Discovery Engine |-->| Reputation Engine |-->| Dynamic Scheduler |  |
|  +------------------+   +-------------------+   +--------------------+  |
|                                                           |             |
|                                                           v             |
|                                                +---------------------+  |
|                                                | Tunnel & Route Mgr  |  |
|                                                +---------------------+  |
+-----------------------------------------------------------|-------------+
                                                            |
                 +------------------------------------------+
                 |
                 v
+---------------------------------+      +--------------------------------+
|          Xray-core              |      |          Linux Kernel          |
|                                 |      |                                |
| [Inbound SOCKS5 / HTTP: 1080]   |      | Netfilter / iptables:          |
|               |                 |      |   Restore CONNMARK -> fwmark   |
|               v                 |      |                                |
| Outbounds:                      |      | Policy Routing (ip rule):      |
|   exit-0 (SO_MARK=100) -------->|----->|   fwmark 100 -> Table 100 (tun0)
|   exit-1 (SO_MARK=101) -------->|----->|   fwmark 101 -> Table 101 (tun1)
|   exit-2 (SO_MARK=102) -------->|----->|   fwmark 102 -> Table 102 (tun2)
+---------------------------------+      +--------------------------------+
```

### 1. 策略路由与连接追踪

- 流量出站时，Xray-core 在底层套接字上打上 `SO_MARK`（100, 101, 102...）。
- 内核根据 `ip rule` 规则将不同 mark 的数据包重定向至对应的独立路由表（Table 100, 101, 102...），各路由表的默认网关指向对应的 `tunX` 虚拟网卡。
- 通过 `iptables` 与 `CONNMARK` 维持连接亲和性，确保已建立 TCP 会话在生命周期内不跨出口跳变。

### 2. 槽位状态机与零中断排空 (Draining)

每个出口槽位支持以下三种状态流转：

- `ACTIVE`：槽位处于活动出站集，承载存量连接与新入站连接。
- `DRAINING`：
  - 槽位从 Xray 负载均衡可用集中移除，所有新连接立即旁路至其余活动槽位。
  - 存量长连接通过连接追踪保护继续在当前隧道维持通信，直到对端或客户端主动关闭。
  - 调度器监控存量连接数与吞吐量，待排空超时或存量清零后销毁隧道。
- `DEAD`：隧道断开或排空结束，内核策略路由规则被撤除，进程被回收。

### 3. 防泄漏与故障阻断 (Fail-Closed)

- **IPv4 故障阻断**：当活动槽位全部离线时，系统阻止流量回退到宿主机物理 WAN 网卡，内核直接拒绝非代理流量。
- **IPv6 防泄漏**：配置黑洞路由（`blackhole`）与不可达策略规则（`unreachable`），彻底阻断通过 IPv6 的隐式旁路泄漏。
- **DNS 防泄漏**：通过防火墙阻断向宿主机上游 DNS 递归服务器发送的明文 UDP/53 与 TCP/53 查询，强制所有 DNS 解析经过代理隧道内部解析。

### 4. 凭据内存生命周期与安全隔离

- 从 VPN 供应商获取的原始 OpenVPN 配置文件与私钥在数据库层面声明 `gorm:"-"`，绝不持久化落盘至 SQLite 数据库文件。
- 内存凭据缓存绑定节点唯一 ID，生命周期与节点状态挂钩，并在节点进入 `DEAD` 或 `FAILED` 状态时立即逐出。
- OpenVPN 配置解析器采用严格指令白名单，剥离 `up`、`down`、`script-security` 等脚本执行类危险参数。

---

## 依赖与运行环境

- **操作系统**：Linux (Ubuntu 20.04+, Debian 11+, CentOS/RHEL 8+)
- **系统内核**：开启 `CONFIG_IP_MULTIPLE_TABLES` 策略路由支持
- **运行权限**：`root` 权限，或具备 `CAP_NET_ADMIN`、`CAP_NET_RAW` 与 `CAP_NET_BIND_SERVICE` 的特权用户
- **运行时系统工具**：
  - `openvpn`
  - `iproute2` (`ip`)
  - `iptables`
  - `ca-certificates`

---

## 生产部署流程

### 1. 组件关系与定位

- **Super-Proxy (本仓库)**：运行在 Linux 出口网关服务器的底层核心 Daemon。负责策略路由维护、OpenVPN 多隧道并发、连接平滑排空（Draining）、防泄漏阻断（Fail-Closed）、Xray 运行时监督与 VLESS Reality 入站代理（TCP 443）。同时开放 Control Plane Management API（TCP 60000）。
- **Super-Proxy Manager (官方 WebUI 管理端)**：独立部署的可视化集中控制台项目：[https://github.com/NaNA1337/super-proxy-manager](https://github.com/NaNA1337/super-proxy-manager)。Manager 通过 HTTPS 与 API Bearer Token 连接节点的 60000 端口，实现出口槽位监控、主动故障切换、节点信誉审查以及统一获取客户端配置。

### 2. 前置准备与网络规划

1. **操作系统支持**：Linux (Debian 11/12, Ubuntu 20.04/22.04/24.04, CentOS/RHEL 8/9)。
2. **系统依赖工具**：
   ```bash
   sudo apt-get update && sudo apt-get install -y openvpn iproute2 iptables ca-certificates curl
   ```
3. **Xray-core 安装**：
   系统内置的 Xray Supervisor 负责调用 `xray` 二进制，请确保系统中已安装 `xray`（建议路径 `/usr/local/bin/xray` 或 `/usr/bin/xray`）：
   ```bash
   bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
   ```
4. **端口与防火墙规则**：
   生产环境严格实施最小端口暴露面原则：
   - **TCP 443**：放行公网入站（专用于 VLESS + Reality + XTLS Vision 客户端入口）。
   - **TCP 60000**：Control Plane Management API。若 Web Manager 独立部署在管控机器，建议防火墙只允许 Manager 服务器 IP 访问；若同机或本地访问，可绑定 `127.0.0.1:60000`。
   - 其余入站端口全部 DROP。

### 3. 安装 Super-Proxy

#### 方式一：Debian / Ubuntu 预编译安装包（推荐）

从 GitHub Releases 获取标准规范命名的 `.deb` 安装包：

```bash
# 下载 Release 发布的规范 deb 安装包
wget https://github.com/NaNA1337/super-proxy/releases/download/v1.1.0/super-proxy_1.1.0_amd64.deb

# 安装软件包
sudo dpkg -i super-proxy_1.1.0_amd64.deb
sudo apt-get install -f -y
```

安装包将自动部署以下组件：
- 核心二进制：`/usr/bin/super-proxy`、`/usr/bin/super-proxy-benchmark`
- 配置文件：`/etc/super-proxy/config.yaml`（权限设为 0600）
- Systemd 守护进程服务单元：`/lib/systemd/system/super-proxy.service`

#### 方式二：源码编译

```bash
git clone https://github.com/NaNA1337/super-proxy.git
cd super-proxy
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o super-proxy ./cmd/manager
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o super-proxy-benchmark ./cmd/benchmark
sudo install -m 755 super-proxy /usr/bin/
sudo install -m 755 super-proxy-benchmark /usr/bin/
```

### 4. 配置文件指南 (`/etc/super-proxy/config.yaml`)

配置文件默认位于 `/etc/super-proxy/config.yaml`：

```yaml
# 出口节点区域偏好
region:
  primary: JP
  fallback:
    - KR
    - SG

# 数据库存储路径（存储节点元数据与健康状态，私钥仅常驻内存）
database:
  path: /etc/super-proxy/xray_manager.db

# 节点发现来源与刷新周期（分钟）
discovery:
  url: "http://www.vpngate.net/api/iphone/"
  interval: 15

# IP 信誉过滤引擎（选填）
reputation:
  enabled: false
  failure_policy: allow  # allow: 查库失败时放行; block: 查库失败时拒绝
  api_key: ""            # AbuseIPDB API 密钥（选填）

# Control Plane API 控制面服务
api:
  listen: "0.0.0.0"
  port: 60000
  key: "your-strong-production-api-token"  # 务必修改为强随机 API Token

# Xray VLESS Reality 入口服务
xray:
  vless:
    enabled: true
    port: 443
    flow: "xtls-rprx-vision"
    dest: "www.microsoft.com:443"
    server_names:
      - "www.microsoft.com"
    fingerprint: "chrome"
    outbound_only_443: true
```

#### 环境变量覆盖（可选，优先级高于配置文件）

可通过环境变量或 systemd service 文件注入参数：
- `AGENT_API_KEY`: Control Plane Bearer Token
- `XRAY_VLESS_ENABLED`: `true`
- `XRAY_VLESS_ADDRESS`: 节点对外连接公网 IP 或解析域名
- `XRAY_VLESS_UUID`: 指定客户端连接 UUID（未指定时自动生成持久化）
- `XRAY_VLESS_PUBLIC_KEY`: Reality X25519 公钥
- `XRAY_VLESS_PRIVATE_KEY`: Reality X25519 私钥（仅用于 Xray 运行时配置，API 绝不外泄）
- `XRAY_VLESS_SHORT_ID`: Reality 16 进制短 ID

### 5. 守护进程管理

```bash
# 重载服务并设置开机启动
sudo systemctl daemon-reload
sudo systemctl enable --now super-proxy

# 检查服务运行状态
sudo systemctl status super-proxy

# 实时查看守护进程日志
sudo journalctl -u super-proxy -f
```

### 6. 运行验证与诊断

```bash
# 1. 运行内核策略路由与接口诊断
sudo super-proxy diagnose routing

# 2. 检查节点健康与基础状态
curl -k -H "Authorization: Bearer <API_KEY>" https://127.0.0.1:60000/api/v1/status

# 3. 检查出口槽位分配与活动隧道 IP
curl -k -H "Authorization: Bearer <API_KEY>" https://127.0.0.1:60000/api/v1/current-exits

# 4. 验证统一客户端配置包接口（确认 443 端口与各 profile 正常生成）
curl -k -H "Authorization: Bearer <API_KEY>" https://127.0.0.1:60000/api/v1/client-config/all
```

### 7. 对接官方 WebUI Manager

官方前端管理后台：[https://github.com/NaNA1337/super-proxy-manager](https://github.com/NaNA1337/super-proxy-manager)

1. 部署并启动 `super-proxy-manager` 容器或服务。
2. 在 Manager 管理后台添加当前节点实例：
   - **Node URL**：`https://<EGRESS_NODE_IP>:60000`
   - **API Token**：填写 `/etc/super-proxy/config.yaml` 中配置的 `key`（或 `AGENT_API_KEY`）
3. 接入后，WebUI Manager 可集中查看各出口槽位状态、手动触发节点故障切换与连接排空，并通过 `/api/v1/client-config/all` 一键向用户分发全部客户端配置。

---

## Control Plane API 接口

Control Plane 服务默认监听于 `https://127.0.0.1:60000`，所有接口强制启用 TLS 传输，并在请求头中验证 Bearer Token：

```text
Authorization: Bearer <your-configured-api-key>
```

### 接口列表

| 方法 | 路径 | 说明 |
| :--- | :--- | :--- |
| `GET` | `/healthz` | 服务健康检查 |
| `GET` | `/metrics` | Prometheus 监控指标数据 |
| `GET` | `/api/v1/current-exits` | 获取当前所有出口槽位分配、节点 IP 与活跃状态 |
| `GET` | `/api/v1/pool/qualified` | 查询当前通过质量与信誉检测的合格备用节点池 |
| `POST` | `/api/v1/slots/{slot_id}/switch` | 触发指定槽位的手动故障切换与排空迁移 |
| `GET` | `/api/v1/operations/{op_id}` | 查询异步状态机任务进展与执行结果 |
| `GET` | `/api/v1/client-config/all` | 统一获取全部客户端配置与分享信息包（Manager 官方推荐 Canonical API） |
| `GET` | `/api/v1/client-config` | 查询客户端聚合配置（含分享链接、Clash/Sing-box/Xray 配置结构体） |
| `GET` | `/api/v1/export/clash` | 导出 Clash Meta (Mihomo) 配置文件（YAML 格式） |
| `GET` | `/api/v1/export/singbox` | 导出 Sing-box 客户端完整配置（JSON 格式） |
| `GET` | `/api/v1/export/xray` | 导出 Xray-core 客户端独立配置（JSON 格式） |
| `GET` | `/api/v1/export/sub` | 导出标准 Base64 订阅（支持 `?token=<API_KEY>` 参数直连订阅） |

### 调用示例

#### 1. 查看当前出站槽位状态

```bash
curl -k -H "Authorization: Bearer <API_KEY>" \
  https://127.0.0.1:60000/api/v1/current-exits
```

响应示例：
```json
{
  "code": 0,
  "data": [
    {
      "slot": 0,
      "interface": "tun0",
      "ip": "203.0.113.10",
      "country": "JP",
      "state": "ACTIVE",
      "last_check": "2026-09-10T04:00:00Z"
    },
    {
      "slot": 1,
      "interface": "tun1",
      "ip": "198.51.100.25",
      "country": "KR",
      "state": "ACTIVE",
      "last_check": "2026-09-10T04:00:00Z"
    }
  ]
}
```

#### 2. 手动发起槽位切换

```bash
curl -k -X POST -H "Authorization: Bearer <API_KEY>" \
  -H "Content-Type: application/json" \
  -d '{"target_node_id": "jp-tokyo-node-01"}' \
  https://127.0.0.1:60000/api/v1/slots/0/switch
```

响应返回异步操作 ID：
```json
{
  "code": 0,
  "operation_id": "op_9f83a21b",
  "status": "PENDING"
}
```

#### 3. 轮询操作执行状态

```bash
curl -k -H "Authorization: Bearer <API_KEY>" \
  https://127.0.0.1:60000/api/v1/operations/op_9f83a21b
```

当 `status` 变为 `COMPLETED` 时，说明旧槽位已完成排空且新节点已成功挂载接管。

---

## 客户端配置接入与导出

Super-Proxy 提供标准 VLESS + Reality 代理入站，支持流控 `xtls-rprx-vision`、uTLS 指纹模拟 `chrome`、SNI 伪装目标 `www.microsoft.com:443`（伪装探测端口固定为 443）与出站仅放行 443 端口限制。

### 生产公网端口策略

生产环境严格限制公网暴露面为两个指定端口，其余端口全部 DROP：

- **TCP 443**：专属于 VLESS + Reality + XTLS Vision 公网客户端入口。
- **TCP 60000**：专属于 Web Manager 与 Management API。

```text
TCP 443   → VLESS + Reality + XTLS Vision (Xray public client ingress)
TCP 60000 → Web Manager / Management API (HTTPS / TLS)
其余端口   → DROP
```

所有客户端配置（VLESS URI、Clash Meta、Sing-box、Xray JSON、Subscription）统一直接来源于实际运行中的 Xray Inbound 运行时端点（TCP/443）。当 Xray 处于停止、崩溃或未就绪状态时，端点自动注销并触发 Fail-Closed，拒绝导出理论失效配置；公网分享链接禁止回退至 localhost/127.0.0.1。

### 0. 统一客户端配置包（Manager 官方主入口 Canonical API）

`GET /api/v1/client-config/all` 是 Manager 获取完整客户端配置的 canonical API。Manager 不应该自行实现 Reality/VLESS 参数拼接，调用此接口即可一次性获取当前真实运行状态下所有可用客户端配置。

```bash
curl -k -H "Authorization: Bearer <API_KEY>" \
  https://<SERVER_IP>:60000/api/v1/client-config/all
```

统一响应模型 `ClientConfigBundle`：
- `schema_version`: 协议版本（数值 `1`）
- `generated_at`: UTC 生成时间戳（RFC3339）
- `node`: 节点元数据（`id`, `name`, `region`, `country`, `status`）
- `endpoint`: 客户端连接公网入口（`address`, `port: 443`, `network: "tcp"`, `protocol: "vless"`, `tls: true`）
- `reality`: Reality 握手参数（`server_name: "www.microsoft.com"`, `fingerprint: "chrome"`, `flow: "xtls-rprx-vision"`, `destination: "www.microsoft.com:443"`）
- `profiles`: 聚合的多客户端配置列表（全部对应运行时 443 端点）：
  - `vless`: 标准 `vless://` URI 链接
  - `clash-meta`: 开箱即用的 Clash Meta (Mihomo) YAML 完整配置文件
  - `sing-box`: 开箱即用的 Sing-box JSON 完整配置文件
  - `xray`: 原生 Xray-core JSON 客户端配置文件
  - `subscription`: 标准 Base64 订阅内容

> **安全与一致性保证**：
> 1. **唯一事实来源**：配置直接来源于 Xray 运行实例登记的真实运行时端点（Runtime VLESS Endpoint）。
> 2. **Fail-Closed 保护**：当 Xray 停止、崩溃或未就绪时，接口立即返回 HTTP 400 (`runtime client endpoint unavailable`)，杜绝假端点或 localhost 泄漏。
> 3. **防信息泄露**：绝不返回 Reality 私钥、OpenVPN 密钥、Agent API token 或其他敏感 Secret。

### 1. 通用订阅与分享链接 (v2rayN / v2rayNG / Shadowrocket / NekoBox / Karing)

- **标准分享链接**：通过 `/api/v1/client-config` 中的 `share_link` 获取标准 `vless://` 链接，直接复制导入。
- **Base64 订阅导入**：
  在客户端订阅管理器中添加以下订阅 URL（支持 URL Query 参数认证）：
  ```text
  https://<SERVER_IP>:60000/api/v1/export/sub?token=<API_KEY>
  ```

### 2. Clash Meta / Mihomo

可直接将订阅地址填入 Clash Meta 订阅列表，或导出单文件配置文件：
```bash
# 导出完整 Clash Meta profile (YAML)
curl -k "https://<SERVER_IP>:60000/api/v1/export/clash?token=<API_KEY>" -o config.yaml
```

单节点配置格式参考：
```yaml
proxies:
  - name: Super-Proxy-VLESS
    type: vless
    server: <SERVER_IP>
    port: 443
    uuid: <UUID>
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: www.microsoft.com
    reality-opts:
      public-key: <PUBLIC_KEY>
      short-id: <SHORT_ID>
    client-fingerprint: chrome
```

### 3. Sing-box

导出开箱即用的 Sing-box 客户端完整 JSON 配置：
```bash
curl -k "https://<SERVER_IP>:60000/api/v1/export/singbox?token=<API_KEY>" -o config.json
```

出站节点格式参考：
```json
{
  "type": "vless",
  "tag": "proxy",
  "server": "<SERVER_IP>",
  "server_port": 443,
  "uuid": "<UUID>",
  "flow": "xtls-rprx-vision",
  "network": "tcp",
  "tls": {
    "enabled": true,
    "server_name": "www.microsoft.com",
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    },
    "reality": {
      "enabled": true,
      "public_key": "<PUBLIC_KEY>",
      "short_id": "<SHORT_ID>"
    }
  },
  "packet_encoding": "xudp"
}
```

### 4. 原生 Xray-core Client

导出原生 Xray-core 独立运行配置文件（包含本地 socks 10808 和 http 10809 入站）：
```bash
curl -k "https://<SERVER_IP>:60000/api/v1/export/xray?token=<API_KEY>" -o config.json
xray run -c config.json
```

---

## 性能基准测试工具

项目随包提供 `super-proxy-benchmark` 测试程序，用于直接评估指定出口隧道或多出口聚合时的真实吞吐量、延迟、丢包率与 CPU 占用率。

```bash
# 测试指定单网卡
super-proxy-benchmark -interfaces tun0 -duration 10

# 并发基准测试多出口聚合吞吐
super-proxy-benchmark -tunnels 3 -interfaces tun0,tun1,tun2 -duration 15
```

---

## 测试套件

仓库提供完整的自动化测试集合，涵盖单元测试、竞态检测与需 root 权限执行的网络名称空间集成测试：

```bash
# 运行单元测试
go test -v ./...

# 运行竞态检测
go test -race ./...

# 运行内核策略路由与抓包集成测试（需 root 权限）
sudo go test -v -count=1 ./tests/integration/...
```

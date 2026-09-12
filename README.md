# Super-Proxy

Super-Proxy 是运行在 Linux 服务器上的多出口代理核心。它自动获取 VPN Gate 节点，维护 3 条活动 OpenVPN 出口和 2 条备用隧道，并通过一个 VLESS Reality 入口对外服务。

```text
客户端 → TCP/443 VLESS Reality → Xray → 路由表 100/101/102 → 3 个 OpenVPN 出口
                                            ↑
                     Manager → HTTPS/60000 Agent API
```

当前稳定版为 [v1.1.7](https://github.com/NaNA1337/super-proxy/releases/tag/v1.1.7)，已实测 VPN Gate 获取、三出口、Reality HTTPS、手动切换以及 [Super-Proxy Manager](https://github.com/NaNA1337/super-proxy-manager) 联动。

### 三条 TUN 如何使用带宽

Xray 对每个新 TCP/UDP 会话按轮询顺序选择 slot 0/1/2 当前对应的活动 TUN。多个下载连接、多个用户或浏览器并发请求可以同时占用三条隧道；已有连接在其生命周期内保持原出口。备用 TUN 晋升后接口名可能是 `tun3` 或 `tun4`，槽位和 fwmark 才是固定标识。

单个 TCP 连接不会把数据包拆到三个 VPN Gate 出口。三个出口使用不同公网源 IP，逐包切换会破坏 TCP 会话。需要单连接叠加时必须另建一个共同的远端聚合端，并在两端部署 MPTCP、MLVPN 或同类 bonding；公共 VPN Gate 节点本身不能充当该聚合端。

Dashboard 的每个槽位速度是该隧道的独立准入测速。三槽总容量是三个活动槽位测速值之和，它只表示多连接可利用的容量。安装包内的实测工具会同时通过活动策略路由表 100/101/102 发起多连接下载：

```bash
sudo super-proxy-benchmark -tunnels 3 -connections-per-tunnel 4 -duration 15
```

工具会从活动路由表读取真实 TUN 接口并设置对应 `SO_MARK`。默认测试三槽，每槽四个并发连接；测试目标、宿主机网卡和 VPN Gate 节点本身都可能成为瓶颈。

## 5 分钟部署

适用于使用 systemd 的 Ubuntu/Debian `amd64` 或 `arm64` 服务器。需要 root、可用的 `/dev/net/tun`、公网 IPv4 或解析到本机的域名，以及未被其他程序占用的 TCP/443。

### 1. 安装 Xray

Super-Proxy 会自行启动和监控 Xray，但不会把 Xray 二进制打进安装包。使用 [XTLS 官方安装脚本](https://github.com/XTLS/Xray-install) 安装：

```bash
curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh -o /tmp/install-xray.sh
sudo bash /tmp/install-xray.sh install

# Super-Proxy 自己管理 Xray，停用安装脚本创建的独立服务，避免端口冲突。
sudo systemctl disable --now xray.service 2>/dev/null || true
xray version
```

### 2. 安装 Super-Proxy

```bash
VERSION=1.1.7
ARCH="$(dpkg --print-architecture)"
case "$ARCH" in amd64|arm64) ;; *) echo "不支持的架构: $ARCH"; exit 1 ;; esac

mkdir -p /tmp/super-proxy-install
cd /tmp/super-proxy-install
curl -fLO "https://github.com/NaNA1337/super-proxy/releases/download/v${VERSION}/super-proxy_${VERSION}_${ARCH}.deb"
curl -fLO "https://github.com/NaNA1337/super-proxy/releases/download/v${VERSION}/super-proxy_${VERSION}_${ARCH}.deb.sha256"
sha256sum -c "super-proxy_${VERSION}_${ARCH}.deb.sha256"
sudo apt-get update
sudo apt-get install -y "./super-proxy_${VERSION}_${ARCH}.deb"
super-proxy --version
```

安装包会先创建安全的“仅管理”配置，不会自动启动服务或开放公网端口。下面一步会为首次部署生成完整且固定的 API Token、UUID、Reality 密钥和 short ID。

### 3. 生成生产配置

以下命令只用于首次安装。已有可用配置时不要重新生成，否则现有客户端和 Manager 凭据会失效。

```bash
# 自动读取本机公网 IPv4；使用域名时直接改成 PUBLIC_ADDRESS=proxy.example.com。
PUBLIC_ADDRESS="$(curl -4fsS https://api.ipify.org)"
test -n "$PUBLIC_ADDRESS" && echo "公网入口: $PUBLIC_ADDRESS"

# Manager 同机运行用 127.0.0.1；异机运行优先填写服务器内网 IP。
# 只有没有内网互通时才用 0.0.0.0，并用防火墙限制 Manager 来源。
API_LISTEN=127.0.0.1

# 保存安装包创建的仅管理配置，再生成完整配置。
sudo mv /etc/super-proxy/config.yaml /etc/super-proxy/config.management-only.yaml
sudo super-proxy-init-config \
  -address "$PUBLIC_ADDRESS" \
  -api-listen "$API_LISTEN" \
  -output /etc/super-proxy/config.yaml
sudo chmod 600 /etc/super-proxy/config.yaml
```

如果服务器在 NAT、CDN 或负载均衡器之后，自动获取的地址可能不正确，请显式设置真实入口 IP 或域名。Reality 必须直接收到客户端的 TCP 连接，普通 HTTP CDN 不能代转 VLESS Reality。

### 4. 启动

```bash
# UFW 用户只需对客户端开放 443；云厂商安全组也要放行 TCP/443。
sudo ufw allow 443/tcp 2>/dev/null || true

# 异机 Manager 才需要这一条；将地址替换为 Manager 的固定来源 IP。
# sudo ufw allow from 198.51.100.20 to any port 60000 proto tcp

sudo systemctl daemon-reload
sudo systemctl enable --now super-proxy
sudo systemctl status super-proxy --no-pager
```

启动成功后应监听：

| 端口 | 默认监听 | 用途 |
| --- | --- | --- |
| TCP/443 | `0.0.0.0` | 客户端 VLESS Reality |
| TCP/60000 | `127.0.0.1` 或配置的管理地址 | Manager / Agent HTTPS API |
| TCP/1080 | `127.0.0.1` | 本机 SOCKS5 |
| TCP/10085 | `127.0.0.1` | Xray 内部 API |

检查端口和日志：

```bash
sudo ss -lntp | grep -E ':(443|60000|1080|10085)\b'
sudo journalctl -u super-proxy -n 100 --no-pager
```

### 5. 验收并导出客户端配置

```bash
export XRAY_MANAGER_API_KEY="$(sudo awk '/^[[:space:]]*key:/ {print $2; exit}' /etc/super-proxy/config.yaml)"
export AGENT_CERT=/etc/super-proxy/cert.pem
API_EXAMPLE=/usr/share/doc/super-proxy/examples/agent-api.sh

"$API_EXAMPLE" /health/ready
"$API_EXAMPLE" /api/v1/status
"$API_EXAMPLE" /api/v1/current-exits
"$API_EXAMPLE" /api/v1/client-config/all > "$HOME/super-proxy-client-bundle.json"
"$API_EXAMPLE" /api/v1/export/xray > "$HOME/xray-client.json"
unset XRAY_MANAGER_API_KEY
```

`current-exits` 初次可能是 `[]`。VPN Gate 节点发现、连接和测速通常需要几十秒，个别公共节点失效后程序会自动尝试其他节点。使用下面命令持续观察，直到出现 3 个活动出口：

```bash
sudo journalctl -fu super-proxy
```

### 出口 ASN 与代理准入

基础 ASN、ISP 和组织归属查询默认启用，不需要 API Key。它会拒绝明确属于云厂商、VPS、托管和数据中心的网段。系统同时检查 VPN Gate 服务器端点与隧道实际出口，并保证活动/备用节点的 IPv4 `/24` 不重复。

精确识别活跃 VPN、公共代理、Tor 和近期代理活动需要信誉供应商数据。推荐使用 [IPQualityScore Proxy & VPN Detection API](https://www.ipqualityscore.com/proxy-vpn-tor-detection-service)：当前 Core 已直接处理 `proxy`、`vpn`、`active_vpn`、`tor`、`active_tor`、`recent_abuse`、`frequent_abuser`、`high_risk_attacks`、`abuse_velocity`、`fraud_score`、ASN 和连接类型。申请 Key 后只需写入服务端配置，不要发送给 Manager 或客户端：

```yaml
reputation:
  enabled: true
  failure_policy: conservative
  ipqs_key: "你的-IPQS-Key"
```

```bash
sudo systemctl restart super-proxy
sudo journalctl -u super-proxy -n 100 --no-pager | grep -E 'Reputation|REJECTED|/24'
```

IPQS 免费额度适合验证配置，不适合持续发现大量 VPN Gate 节点；当前 [官方套餐页](https://www.ipqualityscore.com/plans) 会列出实时额度。Core 会缓存单个供应商结果 24 小时，但一次新节点发现仍可能同时检查服务器端点和实际隧道出口。正式使用应选择足够的月度/每日请求量，避免触发 429 后在 `conservative` 策略下因 UNKNOWN 暂停节点晋升。

如果更需要大量 ASN、hosting、VPN/proxy/Tor 查询，而不要求 IPQS 的近期滥用字段，也可以配置 `ipinfo_key` 使用 [IPinfo Privacy Detection](https://ipinfo.io/products/proxy-vpn-detection-api)。AbuseIPDB 和 GreyNoise 适合作为恶意活动补充，不应单独承担活跃公共代理/VPN 判断。

`hosting/datacenter`、`VPN`、`public proxy`、`Tor`、黑名单和保守模式下的 `UNKNOWN` 都是硬拒绝，VPN Gate 分数和测速结果不能覆盖这些结论。

OpenVPN 私钥只保存在 Core 进程内存中，不写入数据库。Core 刚重启时，旧节点会暂时标记为 `STALE` 并从手动切换候选中隐藏；本轮 VPN Gate 刷新重新取得配置后才恢复。日志出现 `Refreshed ... nodes` 后刷新 Manager 页面即可。无凭据节点不会再创建一个随后失败的切换任务。

将 `$HOME/xray-client.json` 安全复制到客户端，先检查再启动：

```bash
xray run -test -c xray-client.json
xray run -c xray-client.json
```

导出的 Xray 客户端默认在 `127.0.0.1:10808` 提供 SOCKS5。另开终端验证实际出口：

```bash
curl --proxy socks5h://127.0.0.1:10808 https://api.ipify.org
```

返回值应是 VPN 出口地址，而不是服务器自身公网地址。公网出站只允许目标 TCP/443，请使用 HTTPS 测试。

## 升级

升级会保留 `/etc/super-proxy/config.yaml`、TLS 证书和数据库。不要重新运行 `super-proxy-init-config`。

```bash
sudo cp -a /etc/super-proxy "/etc/super-proxy.backup.$(date +%Y%m%d-%H%M%S)"

VERSION=1.1.7
ARCH="$(dpkg --print-architecture)"
curl -fLO "https://github.com/NaNA1337/super-proxy/releases/download/v${VERSION}/super-proxy_${VERSION}_${ARCH}.deb"
curl -fLO "https://github.com/NaNA1337/super-proxy/releases/download/v${VERSION}/super-proxy_${VERSION}_${ARCH}.deb.sha256"
sha256sum -c "super-proxy_${VERSION}_${ARCH}.deb.sha256"
sudo apt-get install -y "./super-proxy_${VERSION}_${ARCH}.deb"
sudo systemctl restart super-proxy
super-proxy --version
```

### 清洗老版本数据库

Core 数据库只保存 VPN Gate 节点池、失败计数、测速结果和信誉缓存。API Token、VLESS UUID、Reality 密钥和 short ID 保存在 `/etc/super-proxy/config.yaml`，清洗数据库不会修改它们。

从老版本升级后，如果页面仍显示旧节点、旧信誉结论、无内存凭据的切换候选或异常失败计数，可以执行一次内置清洗命令：

```bash
sudo systemctl stop super-proxy
sudo super-proxy database clean \
  -config /etc/super-proxy/config.yaml \
  -yes
sudo systemctl start super-proxy
sudo journalctl -fu super-proxy
```

命令执行以下步骤：

1. 拒绝在 Core 仍运行时操作。
2. 对 SQLite 执行完整性检查并落盘 WAL。
3. 将旧数据库自动改名为同目录下的 `manager.db.backup-时间戳`。
4. 创建权限为 `0600` 的当前版本空数据库。

启动后 VPN Gate 会重新发现、重新检查信誉并重新测速，活动出口短时间内为空是正常现象。命令要求配置中的 `database.path` 使用绝对路径；默认生产配置已经满足。备份权限固定为 `0600`，但它仍可能包含旧版本曾保存的历史字段，确认新数据库稳定后应妥善归档或删除备份。

需要恢复旧数据时先停止服务，然后将命令输出的备份文件复制回原数据库路径：

```bash
sudo systemctl stop super-proxy
sudo cp -a /etc/super-proxy/manager.db.backup-实际时间戳 /etc/super-proxy/manager.db
sudo systemctl start super-proxy
```

## 接入 Web Manager

同机部署 Manager 时，Agent 保持默认 `127.0.0.1:60000`，无需把管理端口暴露到公网。异机部署时，核心和 Manager 的配置如下：

1. 两台服务器有内网互通：将 `api.listen` 设为核心服务器的内网 IP，例如 `10.0.0.5`。
2. 只能通过公网连接：将 `api.listen` 设为 `0.0.0.0`，然后在系统防火墙和云安全组中仅允许 Manager 的固定来源 IP 访问 TCP/60000。
3. 修改已有配置后执行 `sudo systemctl restart super-proxy`，再用 `sudo ss -lntp | grep ':60000'` 确认监听地址。

不要对所有公网来源开放 TCP/60000。Agent 已强制使用 HTTPS、Bearer Token、证书指纹校验和限速，但来源防火墙仍是远程管理入口的第一层保护。

安装 [Manager v1.0.4](https://github.com/NaNA1337/super-proxy-manager/releases/tag/v1.0.4) 后，用下面的信息添加主机：

| Manager 字段 | 填写内容 |
| --- | --- |
| Address | 核心服务器的公网 IP 或域名 |
| Agent URL | 同机 `https://127.0.0.1:60000`；异机 `https://核心管理IP或域名:60000` |
| Token | `/etc/super-proxy/config.yaml` 中的 `api.key` |
| TLS fingerprint | 下方命令输出的 SHA-256 指纹 |

```bash
sudo openssl x509 -in /etc/super-proxy/cert.pem -noout -fingerprint -sha256
```

Manager 连接回环或 `10.x`、`172.16-31.x`、`192.168.x` 等内网 Agent 地址时，启动 Manager 需要设置 `ALLOW_PRIVATE_HOSTS=true`。公网 Agent 地址不需要这个选项。

## 常见问题

| 现象 | 处理方法 |
| --- | --- |
| `super-proxy.service` 是 disabled/inactive | 安装包不会自动启动；执行 `sudo systemctl enable --now super-proxy` |
| 启动提示找不到 `xray` | 安装 Xray，并确认 `xray version` 可执行 |
| 443 端口占用 | 停止独立 `xray.service`、Nginx/Caddy 或其他占用 443 的服务 |
| 只有 API，分享接口返回 400 | 当前还是 `management-only` 配置；按首次部署步骤生成完整配置 |
| `current-exits` 长时间为空 | 检查 VPN Gate 连通性、OpenVPN 日志、区域设置和系统时间 |
| 外部客户端连不上 | 检查 TCP/443 的 UFW、云安全组、NAT 转发和 `public_address` |
| Manager 无法连接 60000 | 同机用 `https://127.0.0.1:60000`；跨机检查 `api.listen` 和防火墙 |
| Reality 握手失败且配置使用 Microsoft SNI | 保留备份后迁移到生成器当前默认的 `icloud.com:443` |
| 重启后客户端全部失效 | 检查是否误删或重新生成了 `/etc/super-proxy/config.yaml` |

进一步诊断：

```bash
sudo super-proxy diagnose environment
sudo super-proxy diagnose routing
sudo journalctl -u super-proxy -b --no-pager
```

## 从源码构建

Go 版本以 [go.mod](go.mod) 为准。先安装 `openvpn iproute2 iptables conntrack iputils-ping ca-certificates` 和 Xray，然后在仓库根目录执行：

```bash
CGO_ENABLED=0 go build -trimpath -o super-proxy ./cmd/manager
CGO_ENABLED=0 go build -trimpath -o super-proxy-init-config ./cmd/init-config
sudo install -m 755 super-proxy super-proxy-init-config /usr/local/bin/
sudo install -m 644 configs/super-proxy.service /etc/systemd/system/super-proxy.service
sudo install -d -m 700 /etc/super-proxy
sudo super-proxy-init-config -address 你的公网IP或域名 -output /etc/super-proxy/config.yaml
sudo systemctl daemon-reload
sudo systemctl enable --now super-proxy
```

## 开发与完整文档

```bash
go test ./...
go test -race ./...
go vet ./...
sudo bash scripts/test-network.sh
sudo bash scripts/test-manager.sh /root/super-proxy-manager
sudo python3 tests/live/check.py /root/super-proxy-manager
```

- [详细部署、API、手动切换与客户端教程](docs/tutorial.md)
- [可用性检查报告](docs/usability-report.md)
- [生产调试与发布验证](PRODUCTION_DEBUG_REPORT.md)
- [配置示例](configs/config.example.yaml)

核心固定管理 3 个活动槽位和最多 2 个备用隧道。活动接口名可能是 `tun16`、`tun23` 等动态名称；逻辑槽位仍为 0、1、2，对应 mark 和路由表 100、101、102。多个出口共用一个 VLESS 入口，单个分享链接不会固定到某一条 VPN Gate 节点。

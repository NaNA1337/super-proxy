# Super-Proxy

Linux 多出口代理核心：发现 VPN Gate 节点、建立 OpenVPN 隧道，通过 Xray 和 Linux 策略路由管理出口，并提供 HTTPS 管理 API。Web 控制台在独立仓库 [super-proxy-manager](https://github.com/NaNA1337/super-proxy-manager)。

本轮检查从核心 `755b1b7`、Manager `9864745` 开始，当前修复和验证结果见 [可用性检查报告](docs/usability-report.md)。自动实时套件已跑通 VPN Gate 获取、三个活动出口、Manager 接入、五种分享配置及 Reality 实际 HTTPS 流量；具体部署仍应检查自己的活动隧道和实际代理请求。

## 两个项目如何协作

```text
浏览器 → Manager HTTP :8443（生产环境前置 HTTPS）
                    ↓ HTTPS + Bearer Token + 证书指纹
         Super-Proxy Agent :60000
                    ↓ 调度、配置、监控
客户端 → Xray VLESS Reality :443 → 标记 100/101/102 → OpenVPN 出口
```

- 一个核心实例有 3 个活动槽位、最多 2 个备用隧道；出口按区域与质量选择。
- 本机 SOCKS5 为 `127.0.0.1:1080`，Xray 内部 API 为 `127.0.0.1:10085`。
- VLESS 公网端口固定 `443`，Agent 端口固定 `60000`，Manager 默认 `8443` **使用 HTTP**。
- 多个 VPN 出口共用一个 VLESS 入口；选择某个出口查看配置，并不会创建绑定该出口的独立 VLESS 入站。
- 公网 VLESS 出站限制目标端口 443。不要用访问 HTTP/80 来判断它是否正常。

## 从源码部署

需要 Linux、root、TUN、网络名称空间与策略路由支持；核心程序主动检查 root 身份。Go 版本以 [go.mod](go.mod) 为准（声明 1.25.0，依赖可能触发工具链自动下载；本轮实际工具链见检查报告）。安装运行工具：

```bash
sudo apt-get update
sudo apt-get install -y openvpn iproute2 iptables ca-certificates curl openssl
```

还需安装 Xray-core，确保 `xray version` 和 `xray run -test` 可用。请按 Xray 官方安装流程安装二进制。核心自行监督 Xray 子进程；独立的 Xray 服务不能同时占用 443、1080、10085。

在本仓库根目录执行：

```bash
CGO_ENABLED=0 go build -trimpath -o super-proxy ./cmd/manager
sudo install -m 755 super-proxy /usr/local/bin/super-proxy

# 改为这台服务器真实的公网 IPv4 或 DNS 名称。
# 生成的配置包含随机 API Token、UUID、配对密钥和 short ID，权限 0600。
# 命令拒绝覆盖已有配置，重启时请继续使用同一文件。
sudo go run ./cmd/init-config -address proxy.example.com -output /etc/super-proxy/config.yaml
sudo install -m 644 configs/super-proxy.service /etc/systemd/system/super-proxy.service
sudo systemctl daemon-reload
sudo systemctl enable --now super-proxy
sudo systemctl status super-proxy
sudo journalctl -u super-proxy -n 100 --no-pager
```

如果 sudo 环境没有 Go，先 `go build -o init-config ./cmd/init-config`，再 `sudo ./init-config ...`。`proxy.example.com` 是文档占位符，不能用于公网连通验收。

## Debian 包首次启用

`.deb` 安装后会安全地创建一个仅管理配置，但不会自动启用服务或开放公网端口。此时 `xray.vless.enabled: false`、Agent 监听 `127.0.0.1`，所以分享接口返回 400 是预期行为。要提供完整代理服务，先用真实公网地址生成完整配置，再启用服务：

```bash
sudo super-proxy-init-config -address 203.0.113.10 -output /etc/super-proxy/config.production.yaml
# 首次安装且还没有接入 Manager 时，用生成的完整配置替换仅管理配置。
sudo install -m 600 /etc/super-proxy/config.production.yaml /etc/super-proxy/config.yaml
sudo systemctl daemon-reload
sudo systemctl enable --now super-proxy
```

将 `203.0.113.10` 换成服务器真实公网 IP 或 DNS 名称。若已有 Manager 主机、订阅或客户端，替换配置会改变 API Token 和 Reality 凭据；应先备份 `/etc/super-proxy`，并同步更新客户端和 Manager。旧配置若仍使用 `www.microsoft.com`，当前 Xray 版本可能因目标证书过大导致 Reality 握手失败；新生成配置使用 `icloud.com:443`。

生成器默认将数据库、运行时 Xray 配置和 TLS 证书放在配置文件所在目录；路径为绝对路径。核心启动会重写 `xray_config.json`，请编辑 YAML 配置，勿手动编辑生成文件。TLS 证书为自签名证书，Manager 应保存并校验其 SHA-256 指纹。

防火墙按部署实际放行：客户端到 TCP/443，Manager 到 TCP/60000；保留你的 SSH 管理入口。同机 Manager API 保持监听 `127.0.0.1`。分机部署将 `api.listen` 改为服务器管理地址，并只允许 Manager 来源访问。核心 IPv6 防泄漏规则会影响物理网卡 IPv6 入站/出站，首次部署使用 IPv4 管理连接。

## 首次验证

从受信任的本地配置取得 `api.key`，避免把它写进命令历史：

```bash
read -rsp 'Agent API token: ' XRAY_MANAGER_API_KEY; echo
export XRAY_MANAGER_API_KEY
export AGENT_CERT=/etc/super-proxy/cert.pem

# 脚本对自签名证书使用公钥固定校验，不只是关闭证书验证。
./examples/agent-api.sh /api/v1/status
./examples/agent-api.sh /api/v1/current-exits
./examples/agent-api.sh /api/v1/slots
./examples/agent-api.sh /api/v1/client-config/all > client-config.json
sudo super-proxy diagnose routing
```

`current-exits` 为 `[]` 时尚无活动出口。检查发现、OpenVPN 连接、区域筛选和健康检测日志。首次发现依赖外部 VPN Gate，可能失败或较慢。配置导出要求 VLESS 已启用、有效公网地址已配置且真实 Xray 入站就绪；失败返回 HTTP 400。

## 接入 Web Manager

在 `/root/super-proxy-manager`（或你的 Manager 克隆目录）构建：

```bash
./scripts/build.sh
ALLOW_PRIVATE_HOSTS=true ./bin/super-proxy-web \
  -host 127.0.0.1 -port 8443 -data-dir ./data
```

浏览器连接 Manager；远程开发可用 SSH 转发 `8443`。首次账号 `admin`，临时密码输出在 Manager 启动日志，首次登录强制改密。

进入 **Hosts Fleet → Add Host**：

| 字段 | 同机示例 |
| --- | --- |
| Name | 我的出口网关 |
| Address | 核心服务器的公网 IP / DNS 名称 |
| Agent URL | `https://127.0.0.1:60000` |
| Token | 核心 YAML 的 `api.key` |
| TLS fingerprint | 与下方本机命令输出核对 |

```bash
openssl x509 -in /etc/super-proxy/cert.pem -noout -fingerprint -sha256
```

`ALLOW_PRIVATE_HOSTS=true` 用于明确允许回环或内网 Agent 地址；分机公网接入通常不需要。测试连接、保存并设为默认主机，然后查看 Dashboard、Slots Manager 和 Share Links。Manager 必须使用本轮适配后的代码，旧版本会把核心 schema v1 配置包判为不可用。

完整步骤见 [部署和操作教程](docs/tutorial.md)；Manager 的 [README](../super-proxy-manager/README.md) 介绍独立部署和数据备份。

## 配置与 API

[基础配置示例](configs/config.example.yaml) 默认关闭公网 VLESS，只适合起步检查。生产建议用 `cmd/init-config` 生成并保留固定凭据。

- `reputation.enabled: false`：跳过信誉拒绝，但仍进行隧道和健康检测。启用时 `failure_policy` 只支持 `conservative` 或 `lenient`，不支持 `allow/block`。
- `XRAY_MANAGER_API_KEY` 可覆盖 API Token；`AGENT_API_KEY` 不受支持。
- VLESS UUID、私钥、公钥、short ID 以 YAML 为准；未固定的字段可能在重启时变化。生成器一次性固定这些字段。
- `XRAY_VLESS_ENABLED=true` 可开启 VLESS；公网地址优先在 YAML `xray.vless.public_address` 设置。

所有下列接口都需要认证，没有 `/healthz` 路由。一般用 `Authorization: Bearer TOKEN`，导出接口也兼容查询参数 Token，但日常操作优先请求头。

| 方法 | 路径 | 返回 / 用途 |
| --- | --- | --- |
| GET | `/api/v1/status`、`/api/v1/system` | 实例信息、宿主机指标 |
| GET | `/api/v1/current-exits` | JSON 数组；无出口为 `[]` |
| GET | `/api/v1/slots` | `total_configured`、`slots`、`manual_overrides` |
| GET | `/api/v1/pool`、`/api/v1/pool/qualified` | 池统计、候选列表 |
| GET | `/api/v1/nodes`、`/api/v1/nodes/{id}` | 节点分页列表 / 详情 |
| GET | `/api/v1/routing` | 槽位路由信息；内核真实状态需 diagnose 检查 |
| POST | `/api/v1/slots/{slot}/switch` | 请求体 `{"node_id":"真实节点ID"}`，成功 202 |
| GET | `/api/v1/operations/{operation_id}` | 异步操作；终态 `ACTIVE` 或 `FAILED` |
| GET | `/api/v1/client-config/all` | `schema_version: 1`、node、endpoint、reality、profiles |
| GET | `/api/v1/client-config` | 兼容旧版聚合接口 |
| GET | `/api/v1/export/clash`、`/api/v1/export/singbox`、`/api/v1/export/xray`、`/api/v1/export/sub` | YAML / JSON / Base64 订阅 |
| GET | `/metrics` | Prometheus 文本 |

## 开发与测试

```bash
go test ./...
go test -race ./...
go vet ./...
sudo bash scripts/test-network.sh
# 构建两个仓库，在隔离网络/挂载名称空间内跑真实核心、Xray、Manager 和 Chromium：
sudo bash scripts/test-manager.sh /root/super-proxy-manager
```

联调需 Manager 前端依赖和 Playwright Chromium（`cd ../super-proxy-manager/frontend && npx playwright install chromium`）。运行 root 测试前确认是测试环境；核心启动复现测试现已隔离网络与 `/run`。公网 VPN Gate、三出口、Manager 和 Reality 数据链路可用 `sudo python3 tests/live/check.py /root/super-proxy-manager` 在独立网络名称空间中验收。

性能测试工具：`go build -o super-proxy-benchmark ./cmd/benchmark`；先运行 `./super-proxy-benchmark -h` 查看实际参数，在已有可用隧道上测试。

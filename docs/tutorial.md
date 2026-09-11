# 部署、联调和使用教程

## 1. 判断你需要部署哪些组件

一台出口服务器运行 Super-Proxy 核心和由它启动的 Xray/OpenVPN 子进程；一套 Manager 可以连接多台这样的服务器。客户端连核心公网 443，浏览器连 Manager，Manager 连核心 HTTPS/60000。

同机部署时 Manager 默认 HTTP/8443，通过 SSH 转发即可开发访问。若需要网页公网 HTTPS，选另一个 IP、服务器或独立 HTTPS 端口；核心已占用同 IP 的 443。公网规则保留 SSH 管理端口，不要照搬“其他端口全部 DROP”。

## 2. 一次生成、持续保留配置

```bash
# 在核心仓库根目录
CGO_ENABLED=0 go build -o super-proxy ./cmd/manager
go build -o init-config ./cmd/init-config
sudo ./init-config -address 你的公网域名 -output /etc/super-proxy/config.yaml
```

生成器写入随机 Token、UUID、配对 Reality 密钥和 short ID，文件权限 0600。第二次写入同一路径会失败，防止无意间让所有客户端失效。备份并保留这个文件。

默认 API 只绑定回环，数据库与 Xray 运行配置使用配置目录下的绝对路径。异机 Manager 访问时改 `api.listen` 为管理地址并限制来源。默认区域 JP，备用 KR/SG，可在 `region` 修改。VPN Gate 节点质量和在线状态会变化。

信誉默认关闭，此时不以 UNKNOWN 拒绝节点。若启用，添加实际供应商密钥；`conservative` 会拒绝未知信誉，`lenient` 接受未知结果，但不代表信誉良好。

## 3. 启动核心并分层检查

按 README 安装二进制和 systemd 单元。启动后依次检查：

```bash
systemctl status super-proxy
journalctl -u super-proxy -n 100 --no-pager
ss -lntp
ip -br addr
super-proxy diagnose routing
```

预期有 API 60000、本地 SOCKS 1080、Xray 内部 API 10085；启用 VLESS 时有 TCP/443。隧道未就绪时 `tun*` 和活动出口可能为空。

API 调用示例使用受信任的本机证书做公钥固定：

```bash
read -rsp 'Agent API token: ' XRAY_MANAGER_API_KEY; echo
export XRAY_MANAGER_API_KEY
export AGENT_CERT=/etc/super-proxy/cert.pem
./examples/agent-api.sh /api/v1/status
./examples/agent-api.sh /api/v1/current-exits
./examples/agent-api.sh /api/v1/pool/qualified
./examples/agent-api.sh /api/v1/slots
```

跨机调用先通过可信渠道取得该 Agent 证书，再设置 `AGENT_API_URL=https://管理地址:60000` 和 `AGENT_CERT=/本地可信证书路径`。

典型空状态为 `current-exits: []`；槽位接口类似：

```json
{"total_configured":3,"slots":{},"manual_overrides":{}}
```

状态对象直接返回，不包在 `code/data` 中。`/api/v1/status` 的 online 表示 API 进程可响应，不是对外连接测试。

## 4. 在 Manager 中接入

在 Manager 仓库执行 `./scripts/build.sh`，按其 README 启动。首次用日志中的临时 admin 密码登录并改密。添加主机，填写核心地址、HTTPS Agent URL、API Token，核对证书指纹后保存。

同机示例：URL `https://127.0.0.1:60000`，Manager 需设置 `ALLOW_PRIVATE_HOSTS=true`。不要填 `http://`，不要填 Xray 的 443，也不要填 VPN 节点 IP。

保存后设置默认主机，依次查看 Dashboard、Nodes、Slots Manager、Policy Routing、Share Links。空节点状态仍应能正常浏览；Xray 公网入站已准备好时，Share Links 可以显示网关配置。

## 5. 手动切换的正确请求和验收

从候选列表取得真实 `id`，不是 IP、主机名或自行起的名字：

```bash
./examples/agent-api.sh /api/v1/slots/0/switch \
  -X POST -H 'Content-Type: application/json' \
  --data '{"node_id":"从候选池读取的真实ID"}'
# 用上一步返回的 operation_id 替换：
./examples/agent-api.sh /api/v1/operations/实际操作ID
```

成功接受时 HTTP 202，JSON 包含 `operation_id` 和 `status: "accepted"`。之后轮询状态可能为 REQUESTED、PREPARING、CONNECTING、VERIFYING，终态是 ACTIVE 或 FAILED。成功接管不承诺旧连接永不终止；排空有超时和故障边界。

409 表示槽位忙、节点已使用或状态不适合切换；403 可表示信誉策略拒绝。已有任务在核心重启后丢失，应重新查询槽位现状。

## 6. 导出与使用客户端

```bash
./examples/agent-api.sh /api/v1/client-config/all > bundle.json
./examples/agent-api.sh /api/v1/export/clash > clash-meta.yaml
./examples/agent-api.sh /api/v1/export/singbox > sing-box.json
./examples/agent-api.sh /api/v1/export/xray > xray-client.json
./examples/agent-api.sh /api/v1/export/sub > subscription.txt
xray run -test -c xray-client.json
```

bundle 含 `schema_version: 1`、`generated_at`、`node`、`endpoint`、`reality` 和五种 `profiles`。内容来自运行时入口，不需要用户手动拼 SNI 或公钥。无可用 Xray 入口时 HTTP 400；Manager 将该情况显示为 unavailable。

在另一台设备上运行导出的 Xray 客户端：

```bash
xray run -c xray-client.json
# 在另一个终端，通过导出的本地 SOCKS 10808 发起 HTTPS 请求：
curl --proxy socks5h://127.0.0.1:10808 https://你的HTTPS验收站点/
```

客户端出口限制 443，默认 Reality 目标与 SNI 固定为 `www.microsoft.com:443` / `www.microsoft.com`。不要用 HTTP/80 测试。配置中的公网地址必须是可达真实地址，不是文档 example 域名。

## 7. 公网完整验收清单

本地自动测试不替代以下实际环境验收：

1. VPN Gate 发现成功，候选池有目标区域节点。
2. OpenVPN 建立真实 TUN，活动槽位非空，出口 IP 检测成功。
3. 从外部设备完成 VLESS Reality 握手和 HTTPS 请求，观测到 VPN 出口而非宿主机公网 IP。
4. 保持一个实际长连接，切换出口，确认新连接进入新出口，旧连接按排空策略处理。
5. 在独立测试节点上主动断开隧道，确认新代理请求被阻断，未回退物理网卡，并检查 DNS、IPv6 流量。

可记录时间、核心/Manager 提交、隧道 IP、客户端版本、实际响应和抓包结果。失败时保留已脱敏日志，不把 Token、私钥、订阅 URL 放进问题报告。

## 8. 常见问题

| 现象 | 检查方法 |
| --- | --- |
| 核心启动失败 | 配置路径、root、Xray 二进制、443/1080/10085 冲突；查看 journal |
| API 在线但无出口 | 发现源网络、区域筛选、OpenVPN 日志、信誉策略和健康检测 |
| 60000 不通 | 核心启动是否完成，是否把 HTTP 请求发到 HTTPS，api.listen 和防火墙 |
| Share Links 不可用 | VLESS 是否开启，公网地址是否正确，Xray 是否就绪，Manager 是否包含 schema v1 适配 |
| 重启后客户端不能连 | 是否重新生成了未持久化的 UUID/密钥/short ID；使用 init-config 生成的固定配置 |
| 指纹变化 | 是否丢失/替换了配置目录的 cert.pem 和 key.pem |
| 网页仍是旧版本 | 重新构建前端、同步 backend/embedded/dist、重新构建安装 Manager Go 二进制 |
| 订阅重启后失效 | 当前 Manager 订阅存储为内存；重建并分发新链接 |

## 9. 可重复自动联调

```bash
sudo bash scripts/test-manager.sh /root/super-proxy-manager
```

隔离运行真实核心、Xray、Manager、Chromium，检查登录改密、证书固定、API、任务失败路径、五种原样导出、ZIP、订阅和撤销、11 个页面、无过期成功配置、跨 CWD 重启后的凭据稳定性。测试结束清理临时进程和数据；VPN 发现源故意不可达，不把外部 VPN 可用性伪装为已通过。

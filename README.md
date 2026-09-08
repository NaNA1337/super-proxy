# Super-Proxy Egress Manager

Super-Proxy 是一款专为 Linux 环境设计的生产级**多出口代理网关自动调度系统**。它将 **Xray-core**、**OpenVPN** 与 **VPN Gate** 公共节点池结合，并通过原生 Linux 策略路由（iproute2 `fwmark`）实现对上层应用的透明代理分流，同时内置了高度安全的 **Agent API Control Plane** 支持外部远程管理。

## 🌟 核心特性

- **VPN Gate 自动化发掘**: 自动爬取并评估最新的 VPN Gate 节点。
- **动态健康调度器 (Scheduler)**: 后台死循环监控隧道连通性（`ping 1.1.1.1`）。当检测到 `tun` 隧道网络断开或进程崩溃时，自动执行 **Failover（故障转移）**，从 Standby 节点池提拔新节点并无缝重载路由。
- **信誉防线 (Reputation Engine)**: 针对获取到的节点 IP 进行 Abuse 库侦测过滤，防止接入已被各大站长拉黑的脏 IP（支持扩展接入 AbuseIPDB / GreyNoise）。
- **Linux 高级策略路由**: 通过 Socket `mark`（fwmark）机制绑定流量，将 `exit-0`, `exit-1`, `exit-2` 的流量通过各自特定的 `tunX` 网卡安全发出，Xray 自身作为透明的前端负载均衡器。
- **Agent API (Control Plane)**: 高强度鉴权保护的 HTTPS API 服务器。提供强大的节点手动锁定与异步状态机切换能力。
- **Prometheus 监控**: 原生提供 `/metrics` 用于 Grafana 拓扑监控。

## 🚀 部署要求

- 操作系统: **Ubuntu Server** / Linux
- 运行权限: 需要 **root** 权限 (因涉及 `iproute2` 和 `tun` 网卡挂载)
- 依赖项: 安装 `openvpn` 和 `iproute2`

```bash
apt-get update
apt-get install -y openvpn iproute2 iperf3
```

## ⚙️ 快速使用

### 1. 启动管理器

配置所需的环境变量，直接拉起网关进程：

```bash
# 设定您的地区偏好 (如 US, JP, KR 等)
export XRAY_MANAGER_REGION="JP"

# 设定最高安全级别的 API 强鉴权 Key
export XRAY_MANAGER_API_KEY="your-secure-master-key"

# 启动 (需 root)
sudo -E ./super-proxy
```

### 2. 通过 Agent API 管理隧道

所有的 API 探针均监听于 `60000` 端口，强制开启 TLS（自签名），请求头中必须带上强 Token。

**查看系统的出站状态和拓扑**
```bash
curl -k -H "Authorization: Bearer your-secure-master-key" https://127.0.0.1:60000/api/v1/current-exits
```

**获取已筛选出的合格备用节点池 (QUALIFIED)**
```bash
curl -k -H "Authorization: Bearer your-secure-master-key" https://127.0.0.1:60000/api/v1/pool/qualified
```

### 3. 高级：触发手动状态机 (Manual Switch)

如果不满意当前的某个节点，可以直接命令调度器强行进行切换替换。

**第一步：发起请求 (指定替换 Slot 1 的出口 IP 为特定的 node_id)**
```bash
curl -k -X POST -H "Authorization: Bearer your-secure-master-key" \
    -d '{"node_id":"some-qualified-node-id"}' \
    https://127.0.0.1:60000/api/v1/slots/1/switch
```
_您将立即获得一个 `operation_id`。_

**第二步：追踪状态机进展**
```bash
curl -k -H "Authorization: Bearer your-secure-master-key" \
    https://127.0.0.1:60000/api/v1/operations/YOUR_OPERATION_ID
```
当 `status` 流转至 `ACTIVE` 时，说明底层旧路由已被卸载，新进程拨号完毕并成功连接了外网，您的 Xray 的 `exit-1` 流量已经平滑切换。

## 📊 性能基准测试

项目内置了利用 `iperf3` 快速探测连通质量的脚本。
```bash
./scripts/benchmark.sh
```

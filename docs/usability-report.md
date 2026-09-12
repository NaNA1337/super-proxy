# 双项目可用性检查报告

检查日期：2026-09-11 至 2026-09-12（UTC）。检查从核心 `755b1b7`、Manager `9864745` 开始；修复已分批提交并推送，v1.1.2 Debian 包已执行安装与 systemd 验收。

## 结论

修复后的两个项目可以共同完成管理链路：真实核心进程启动 Xray，Manager 通过固定证书的 HTTPS 接入，浏览器登录和操作页面，查询节点/路由/指标，导出五种客户端配置、ZIP 和订阅。核心停止时不返回旧的成功配置，使用生成器配置从 `/` 重启后证书和客户端凭据保持一致。

公网实时套件从 VPN Gate 获取约 96–99 个节点，建立三个 JP 活动出口，将 Manager 连接到真实 Agent，逐项比较五种分享配置，并由真实 Xray Reality 客户端连续请求 HTTPS。观测出口在三条 VPN NAT 出口之间轮转，且隧道保持超过 60 秒。该测试在隔离网络名称空间中运行，验证了完整数据链路，但不代表所有地区、VPN Gate 节点或客户端版本都具有相同稳定性。

## 实际环境

| 项目 | 版本 |
| --- | --- |
| Linux | 7.0.0-30-generic，amd64 |
| Go | go1.26.0 linux/amd64 |
| Xray | 26.3.27，d2758a0 |
| OpenVPN | 2.7.0 |
| Node.js | v22.22.1 |
| 前端构建 | Vite 5.4.21，TypeScript |
| 浏览器 | Playwright Chromium，headless |

## 修复的问题

| 问题 | 实际影响 | 修复和验证 |
| --- | --- | --- |
| Manager 将核心 schema v1 当成旧版 `available/nodes` 响应 | Xray 正常也显示配置不可用 | 适配 node/endpoint/reality/profiles；内容原样传递；真实导出与上游逐项比较 |
| YAML `public_address` 未传给监督器 | Xray 就绪但没有可导出的运行时端点 | 主程序设置监督器公网地址；真实进程配置导出通过 |
| 手动切换创建任务后再修改 ID | 返回的 ID 无法在操作索引查到 | 以租约 ID 创建任务；返回快照避免读写竞争；真实 202→查询→FAILED 路径通过 |
| 空出口返回 null | 页面数组操作可能崩溃 | 出口和节点列表返回空数组；11 个页面空池浏览通过 |
| 核心 API / Manager 页面显示路由号 10000+ | 展示与内核 100+ 不一致 | API 复用路由常量，页面修正；回归核对 100/101/102 |
| 错误认证降低同 IP 额度 | Manager 随后正常请求也遭遇 429 | 已认证/未认证请求使用独立限流桶；回归和真实联调通过 |
| 关闭信誉后仍以默认 conservative 拒绝 UNKNOWN | 默认设置下候选仍可能全部被拒绝 | 关闭信誉时使用不拒绝 UNKNOWN 的引擎策略；启用时保留配置策略 |
| 只给 Reality 私钥时补出随机公钥 | 公私钥不匹配导致客户端无法握手 | 从私钥推导公钥，拒绝显式错配；单测和真实 Xray 配置检查 |
| 凭据生成缺少可重复部署入口 | 默认生成字段重启可能变化 | 新增 init-config，一次固定 Token/UUID/密钥/short ID，0600 且拒绝覆盖 |
| TLS 证书路径依赖 CWD | 换目录重启可能改变证书/指纹 | 主程序使用 YAML 同目录证书路径；从 `/` 重启校验相同证书 |
| 传错显式配置路径会回退示例 | 部署错误被隐藏 | 只有隐式默认路径允许开发示例回退 |
| API IPv6 地址拼接和环境 Token 检查不统一 | IPv6 监听地址错误、公共绑定拒绝环境 Token | 使用 net.JoinHostPort；绑定检查前解析 API Token 覆盖值 |
| `?key=` 日志脱敏未设置更新标志 | key 单参数可能进入日志 | 修复脱敏并加回归 |
| 配置加载使用全局 Viper | 多次加载可能互相影响 | 每次加载使用独立实例 |
| Share Links 依赖必须有 VPN 出口 | 网关入站已就绪但空池无法展示配置 | 空池使用核心返回的网关配置展示，说明不等于已有可通出口 |
| Manager 构建易遗漏前端嵌入步骤 | 前端改了但发布的 Go 二进制还是旧网页 | 新增 build.sh，同步资源后构建；CI 使用 go.mod 工具链和资源同步 |
| root 启动复现测试直接操作宿主网络 | 测试可能干扰实际服务 | 改为网络和挂载名称空间，真正请求 HTTPS 而非只检查日志 |
| 配置目录复现测试只记录失败却不断言 | 回归失败仍可能显示测试通过 | 添加生成成功和文件存在断言 |
| 网络脚本依赖 `table` 文本且 grep -q 配合 pipefail | 实际 `lookup` 输出及 SIGPIPE 导致误报 | 兼容 lookup/table，并完整消费管道输入；脚本通过 |
| README 示例与实际接口不符 | 健康地址、环境变量、切换请求和终态错误 | 两个 README 和教程重写，示例使用实际请求体与响应模型 |

## 测试结果

| 检查 | 结果与范围 |
| --- | --- |
| 核心 `go test ./...` 基线 | 通过，含现有网络/包路径/启动复现测试 |
| 核心 `go test -race -count=1 ./...` 修复后 | 通过，所有包 |
| Manager `go test -race -count=1 ./...` 修复后 | 通过，所有包 |
| 两项目 `go vet ./...` | 通过 |
| Manager `npm run typecheck`、`npm run lint` | 通过；lint 当前等同 tsc，不是 ESLint |
| Manager 前端构建 + CGO_ENABLED=0 Go 构建 | 通过，嵌入更新后的前端资源 |
| Manager 原浏览器 E2E | 14/14 通过，使用模拟 Agent；最后一次 32.6 秒 |
| `scripts/test-network.sh` | 通过，网络名称空间内路由、iptables、IPv6、排空规则 |
| `scripts/test-manager.sh` | 通过，真实核心/Xray/Manager/Chromium，详情如下 |
| `tests/live/check.py` | 通过，真实 VPN Gate、三活动出口、Manager、五种配置、Reality HTTPS 和成功手动切换 |
| systemd 生产部署 | 未安装服务；本地 verify 提示 Manager 目标安装二进制尚不存在，不计为部署通过 |

真实联调断言：

1. 配置生成权限 0600，已有文件不可覆盖。
2. Manager 首次登录、强制改密、主机添加与证书固定成功；核心缺失/错误 Token 分别返回 401/403。
3. 转发 status、system、current-exits、slots、pool、pool/qualified、nodes、routing、metrics 共九类接口。
4. 没有 VPN 凭据的真实候选返回切换 202，操作 ID 可轮询，最终明确 FAILED；不把该路径记为成功 VPN 切换。
5. 五种配置与上游内容逐字一致，原生 Xray 客户端配置通过 `xray run -test`；ZIP 包含所有配置。
6. Manager 订阅内容与核心 VLESS URI 一致，撤销后 403。
7. Chromium 登录后浏览 11 个页面，无 pageerror；空池仍显示网关配置并生成 QR。
8. 核心停止后 Manager 返回 unavailable，不返回旧 profiles/nodes。
9. 核心从 `/` 重启，五种配置和 TLS 证书与重启前完全相同；Manager 恢复配置访问。

简要原始输出保存在 [validation.log](validation.log)，不包含测试凭据。入口脚本 [test-manager.sh](../scripts/test-manager.sh) 可重新运行。

## 仍需明确的边界

- 实时套件使用同一网络名称空间内的客户端连接 Reality 入站，再经真实公网 VPN Gate 出口；尚未覆盖另一地理位置的外部客户端、长时间 soak 或所有地区节点。
- 路由接口的 DNS/IPv6 保护布尔值及前端部分保护标签仍是声明性展示，并非实时内核审计结果。判断保护是否生效要用 diagnose、iptables/ip6tables、策略路由和抓包；不要仅凭绿色标记验收。
- Manager 的订阅和审计、核心异步任务仍以内存存储；重启后的订阅需重建，历史任务和审计不能保证恢复。
- schema v1 描述网关入口，非每个 VPN 出口专属入站。按节点选择下载、区域筛选都不保证连接固定从那个 VPN 节点/国家出口。
- 本轮 `npm audit` 报告 3 个开发依赖问题（1 high、2 moderate）：vite、esbuild、adm-zip；未在本次兼容修复中跨主版本升级依赖。生产 Go 二进制嵌入静态文件，未运行 Vite 开发服务器，但开发工具链问题仍需单独升级验证。Vite 官方 [路径穿越公告](https://github.com/vitejs/vite/security/advisories/GHSA-4w7w-66w2-5vf9) 和 esbuild 官方 [开发服务器公告](https://github.com/evanw/esbuild/security/advisories/GHSA-67mh-4wv8-2f99) 说明相关影响；adm-zip 条目来自本轮 npm audit。

这是一轮功能与联调检查，不是对所有部署环境、客户端版本或安全属性的全面认证。

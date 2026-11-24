# Port Guard

> 部署在爱快（iKuai）路由器 Docker 上的端口映射防护工具。监听被映射到外网的端口，识别扫描 / 爆破 / Flood 行为，自动调用爱快 API 封禁源 IP，到期自动解封。封禁时长、阈值、白名单全部可在 Web 管理界面配置（默认封禁 **30 分钟**）。

## 为什么需要它

端口映射把内网服务暴露到公网后，会立刻成为扫描器的目标：SSH 爆破、Redis/MySQL 未授权访问探测、SYN Flood 等。爱快自带的 ACL 和黑名单是静态规则，不会根据实时行为动态封禁。Port Guard 补上这一环：

- **实时识别**：按源 IP 统计滑动窗口内的连接行为，命中规则立即封禁
- **动态解封**：调用爱快原生黑名单（按分钟生效）或 ACL 规则，到期自动恢复
- **多数据源**：抓包（精准）、Syslog（实时）、连接表轮询（兜底）三路融合
- **抑制误封**：私网地址、白名单 CIDR、非映射端口的流量一律不参与判定

## 检测原理

需要特别说明：**只看爱快日志是不够的**。端口映射本质是 DNAT 放通规则，外部扫描映射端口时，这些连接在爱快眼里是"允许"的，不会出现在拦截日志里。因此 Port Guard 采用三路数据融合：

| 数据源 | 说明 | 依赖条件 |
|---|---|---|
| **AF_PACKET 抓包**（主力） | 直接分析发往映射端口的 SYN / UDP 包，识别 SYN Flood、横向端口扫描 | 容器 host 网络 + `NET_RAW` 能力 |
| **Syslog 接收** | 爱快推送的安全告警、ACL 拒绝日志作为补充信号 | 爱快配置日志服务器指向容器 UDP 5140 |
| **连接表轮询**（兜底） | 定期拉取爱快会话表，按源 IP 统计新建连接频率 | 固件支持连接表 API |

三路事件统一进入检测引擎，按滑动窗口（默认 60 秒）统计，命中以下任一规则即告警：

- `syn_flood`：同一 IP 对同一端口 SYN 数 ≥ 30
- `port_scan`：同一 IP 探测不同端口数 ≥ 8
- `conn_rate`：同一 IP 新建连接数 ≥ 60
- `udp_flood`：同一 IP UDP 包数 ≥ 80
- `syslog`：爱快安全日志明确告警

同一 IP 告警后有 300 秒冷却期，避免重复封禁。所有阈值都可在 Web 界面调整。

## 快速开始

### 1. 构建并启动容器

```bash
docker build -t port-guard:latest .
docker compose up -d
```

默认使用 `network_mode: host`，Web 界面监听爱快的 **8080** 端口：`http://<爱快LAN-IP>:8080`

> 如果不想用 host 网络，把 `docker-compose.yml` 里的 `network_mode: host` 注释掉，启用下面的 `ports` 映射。此时抓包不可用，但 Syslog + API 轮询仍可正常工作。

默认账号：`admin` / `portguard` —— **登录后请立即在「系统配置 → 管理界面」修改密码**。

### 2. 爱快侧配置

**(a) 创建专用管理账号**（推荐）

爱快 Web → 系统设置 → 管理员配置，新建一个只读/受限账号用于 API 调用（或用 admin）。在 Web 界面「系统配置 → 爱快路由器连接」填入地址、账号、密码。

**(b) 配置 Syslog（可选但推荐）**

爱快 Web → 系统设置 → 日志设置 → 日志服务器，填写容器所在主机的 IP、端口 `5140`，协议 UDP，勾选安全日志 / 防火墙日志。

**(c) 确认端口映射**

「系统配置」开启「自动同步端口映射」后，程序会每 5 分钟通过爱快 API 拉取 DNAT 规则，自动识别需要监控的端口。也可以在 Web 界面手工添加。

### 3. 验证封禁功能

进入「系统配置 → 封禁方式」，默认是 `auto`：程序会用一个文档保留地址（`203.0.113.254`）探测爱快的黑名单 / ACL 接口，成功后缓存可用方案。如果自动探测失败，可手动切换为「安全防护黑名单」或「ACL 禁止规则」。

也可以在「封禁管理」页面手工封禁一个测试 IP，观察爱快「策略 → 安全防护 → 黑名单」是否出现对应条目。

## 配置项说明

| 配置 | 默认值 | 说明 |
|---|---|---|
| `ban_duration_minutes` | 30 | 封禁时长（分钟） |
| `ban_mode` | auto | `auto` / `blacklist` / `acl` / `none` |
| `whitelist` | 私网段 | 逗号分隔的 CIDR，永不封禁 |
| `ignore_private_ips` | true | 忽略 RFC1918 私网地址 |
| `window_seconds` | 60 | 统计窗口 |
| `syn_flood_threshold` | 30 | SYN Flood 阈值 |
| `port_scan_threshold` | 8 | 端口扫描阈值（不同端口数） |
| `conn_rate_threshold` | 60 | 连接频率阈值 |
| `udp_flood_threshold` | 80 | UDP Flood 阈值 |
| `alert_cooldown_seconds` | 300 | 同一 IP 告警冷却时间 |
| `sniffer_enabled` | true | AF_PACKET 抓包 |
| `syslog_enabled` | true | Syslog 接收 |
| `conn_poll_enabled` | false | 连接表轮询（需固件支持） |

所有配置均可通过 Web 界面修改，无需重启容器。也可以使用环境变量做首次初始化：`PG_IKUAI_HOST`、`PG_IKUAI_USERNAME`、`PG_IKUAI_PASSWORD`、`PG_IKUAI_PORT`、`PG_IKUAI_SSL`、`PG_WEB_USERNAME`、`PG_BAN_MINUTES`、`PG_SNIFFER_IFACE`。

## HTTP API

管理界面之外提供 JSON API（需先通过 `/login` 获取会话 Cookie）：

```
GET    /api/status          运行状态、各检测源统计
GET    /api/events?limit=100&type=attack   事件日志
GET    /api/bans            封禁列表
GET    /api/config          当前配置（密码脱敏）
POST   /api/config          更新配置（JSON）
GET    /api/ports           监控端口列表
POST   /api/ports           添加监控端口
DELETE /api/ports/{id}      删除监控端口
POST   /api/ban             手工封禁 {"ip":"1.2.3.4","minutes":30,"reason":"..."}
POST   /api/unban           手工解封 {"ip":"1.2.3.4"}
POST   /api/probe           重新探测爱快封禁接口
GET    /health              健康检查
```

## 技术栈与体积

- **Go 1.26+**，纯静态编译，无 CGO
- **SQLite**：`modernc.org/sqlite`（纯 Go 驱动）
- **抓包**：`golang.org/x/sys/unix` AF_PACKET + `gopacket` 解码，不依赖 libpcap
- **Web**：标准库 `net/http` + `html/template`，模板与静态资源 `embed` 进二进制
- 镜像约 20MB，运行内存 15–30MB，`linux/amd64` 与 `linux/arm64` 均可构建

```bash
make test                  # 运行单元测试
make build                 # 本地构建
make docker-build-arm64    # 为爱快 ARM 机型构建镜像
make docker-build-amd64    # 为爱快 x86 机型构建镜像
```

## 安全须知

1. 管理界面默认密码 `portguard` 必须修改；建议不要暴露到公网
2. 爱快 API 使用管理员密码认证，建议创建专用账号并定期更换密码
3. 白名单默认包含全部私网段，防止误封内网设备；如有公网 IP 需要豁免，加入 `whitelist`
4. `ban_mode=none` 可切换为只告警不封禁，用于观察阈值是否合理

## 已知限制

- 爱快不同固件版本的 API 字段名存在差异。封禁接口通过多形态探测自动适配；如果全部失败，请在 Web 界面手动指定 `ban_mode`，或提交 Issue 附上固件版本和 API 返回内容。
- `conn_poll_enabled` 依赖固件是否提供连接表接口（`func_name` 默认 `monitor_conn`），可在配置中修改。
- AF_PACKET 抓包在部分爱快 Docker 环境中可能受内核能力限制；此时程序自动降级到 Syslog + API 检测。

## License

MIT

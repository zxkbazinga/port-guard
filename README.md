# Port Guard

> 部署在爱快（iKuai）路由器上的端口映射防护工具。监听被映射到外网的端口，识别扫描 / 爆破 / Flood 行为，自动调用爱快 API 封禁源 IP，到期自动解封。封禁时长、阈值、白名单全部可配置（默认封禁 **30 分钟**）。
>
> 提供两种部署方式：**爱快应用市场 Docker 应用（.ipkg）** 与 **Docker 镜像（GHCR）**，均由 GitHub Actions 自动构建发布，无需本地编译。

## 为什么需要它

端口映射把内网服务暴露到公网后，会立刻成为扫描器的目标：SSH 爆破、Redis/MySQL 未授权访问探测、SYN Flood 等。爱快自带的 ACL 和黑名单是静态规则，不会根据实时行为动态封禁。Port Guard 补上这一环：

- **实时识别**：按源 IP 统计滑动窗口内的连接行为，命中规则立即封禁
- **动态解封**：调用爱快原生黑名单（按分钟生效）或 ACL 规则，到期自动恢复
- **多数据源**：连接表轮询、Syslog（实时）两路融合；独立部署且网络条件允许时可再开启 AF_PACKET 抓包
- **登录爆破防护**：接收群晖 / Windows / Ubuntu 转发的登录失败日志，同一 IP 失败 3 次即封禁
- **抑制误封**：私网地址、白名单 CIDR、非映射端口的流量一律不参与判定
- **日志自动清理**：事件日志与已解除的封禁历史默认保留 3 天，启动时立即清理并每 6 小时执行一次，数据库不会无限增长

## 检测原理

需要特别说明：**只看爱快日志是不够的**。端口映射本质是 DNAT 放通规则，外部扫描映射端口时，这些连接在爱快眼里是"允许"的，不会出现在拦截日志里。因此 Port Guard 采用三路数据融合：

| 数据源 | 说明 | 依赖条件 |
|---|---|---|
| **连接表轮询**（主力） | 定期拉取爱快会话表，按源 IP 统计新建连接频率与端口分散度 | 固件支持连接表 API，默认开启 |
| **Syslog 接收**（主力） | 爱快推送的安全告警、ACL 拒绝日志，以及群晖 / Windows / Ubuntu 转发的登录失败日志 | 各设备配置日志服务器指向 Port Guard 的 UDP 5140 |
| **AF_PACKET 抓包**（可选增强） | 直接分析发往映射端口的 SYN / UDP 包，识别 SYN Flood、横向端口扫描 | 需 host 网络 + `NET_RAW`；爱快官方 Docker 应用禁止 host 网络，故应用市场部署下不可用 |

三路事件统一进入检测引擎，按滑动窗口（默认 60 秒）统计，命中以下任一规则即告警：

- `syn_flood`：同一 IP 对同一端口 SYN 数 ≥ 30
- `port_scan`：同一 IP 探测不同端口数 ≥ 8
- `conn_rate`：同一 IP 新建连接数 ≥ 60
- `udp_flood`：同一 IP UDP 包数 ≥ 80
- `syslog`：爱快安全日志明确告警
- `login_brute`：同一 IP 登录失败 ≥ 3 次（独立 5 分钟窗口，来自 NAS / Windows / Ubuntu 日志）

同一 IP 告警后有 300 秒冷却期，避免重复封禁。所有阈值都可在 Web 界面调整。

登录爆破防护需要各服务器把日志转发过来，三台机器的配置步骤见 [LOG-FORWARDING.md](docs/LOG-FORWARDING.md)。

## 快速开始

两种部署方式任选其一，都从 [GitHub Releases](https://github.com/zxkbazinga/port-guard/releases) 获取成品，无需本地构建。

### 方式 A：爱快应用市场 Docker 应用（.ipkg，推荐）

前提：爱快已安装并启用 **Docker 插件**。然后进入 **扩展服务 → 应用市场 → 本地安装**，上传 Release 中的 `port-guard-<版本>-ikuai.ipkg`。

ipkg 是 Docker 类型应用（`manifest.json` 中 `type: "1"`），安装后会自动从 `ghcr.io/zxkbazinga/port-guard:<版本>` 拉取镜像并创建容器。爱快 Docker 插件**禁止使用宿主网络**，因此容器用标准 bridge 网络 + 端口映射：Web 管理端口（默认 8080）和 Syslog 接收端口（UDP 5140）都可在应用配置页修改。

> **重要**：bridge 网络下 AF_PACKET 抓包看不到经爱快转发的外部流量，所以应用市场部署下抓包已默认关闭，检测主力是**连接表轮询 + Syslog**（登录爆破防护照常工作）。这是爱快平台的硬性限制，不是功能缺失。

安装后在应用配置页填写爱快管理地址、管理端口、API 账号密码，封禁时长默认 30 分钟可直接改。保存后应用自动重启，点击应用详情页的「打开」即可进入 Web 管理界面（默认端口 8080，可在 `APP_PORT_WEB` 修改）。请确保「轮询爱快连接表」保持开启（`PG_CONN_POLL_ENABLED=1`，默认已开）。

> **管理地址填什么**：容器跑在 bridge 网络里，`127.0.0.1` 指向容器自己，**不要填**。请填爱快的 LAN 地址（如 `192.168.31.1`）。如果填了 LAN 地址仍连不上，可试 Docker 网桥网关地址——也就是你浏览器访问本界面用的那个 IP（如 `172.18.20.1`），它同样指向爱快本机。HTTPS 自签证书已自动跳过校验，按你的爱快实际协议勾选即可。

> 如果你的固件不提供本地安装入口，直接用「方式 B」的 Docker Compose 部署，功能完全一致。

### 方式 B：Docker 镜像（GHCR）

```bash
docker pull ghcr.io/zxkbazinga/port-guard:latest
docker compose up -d
```

默认用 `ports` 端口映射（爱快 Docker 插件禁止宿主网络），Web 界面监听 **8080**、Syslog 监听 UDP **5140**：`http://<爱快LAN-IP>:8080`

> 这种方式下抓包不可用，但连接表轮询 + Syslog 仍可正常工作。若你在普通 Linux 主机上自建、且确实需要抓包，可自行把 `docker-compose.yml` 改为宿主网络并开启 `PG_SNIFFER_ENABLED=1`。

默认账号：`admin` / `portguard` —— **登录后请立即在「系统配置 → 管理界面」修改密码**。

### 爱快侧配置

**(a) 创建专用管理账号**（推荐）

爱快 Web → 系统设置 → 管理员配置，新建一个只读/受限账号用于 API 调用（或用 admin）。在 Web 界面「系统配置 → 爱快路由器连接」填入地址、账号、密码。

**(b) 配置 Syslog（可选但推荐）**

爱快 Web → 系统设置 → 日志设置 → 日志服务器，填写容器所在主机的 IP、端口 `5140`，协议 UDP，勾选安全日志 / 防火墙日志。

**(c) 确认端口映射**

「系统配置」开启「自动同步端口映射」后，程序会每 5 分钟通过爱快 API 拉取 DNAT 规则，自动识别需要监控的端口。也可以在「端口管理」页面查看全部监控端口，并手工添加或删除端口（手工条目不会被自动同步覆盖）。

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
- 静态二进制约 15MB，ipkg 包仅数 KB（只含 compose 与配置，镜像从 GHCR 拉取），Docker 镜像约 39MB，运行内存 15–30MB
- 支持 `linux/amd64` 与 `linux/arm64`

## 自动构建与发布（GitHub Actions）

本项目不需要在本地构建。所有产物由 GitHub Actions 生成：

| Workflow | 触发时机 | 作用 |
|---|---|---|
| `.github/workflows/ci.yml` | push / PR 到 main | 格式检查、go vet、单元测试（含 race）、双架构交叉编译、ipkg 配置校验 |
| `.github/workflows/release.yml` | 推送 `v*` 标签（如 `v1.0.0`） | 构建多架构 GHCR 镜像 + ipkg 包 + 独立二进制，创建 GitHub Release |

发布流程：

```bash
git tag v1.0.0
git push origin v1.0.0
```

推送后自动完成：

1. 构建并推送 Docker 镜像到 `ghcr.io/zxkbazinga/port-guard:1.0.0`（同时更新 `latest`），支持 amd64 / arm64
2. 打包爱快应用市场 Docker 应用 `port-guard-1.0.0-ikuai.ipkg`（引用上面的 GHCR 镜像）
3. 编译 `port-guard-linux-amd64` / `port-guard-linux-arm64` 独立二进制
4. 创建 GitHub Release，把以上文件作为附件上传

> 首次使用 GHCR 无需额外配置：workflow 使用内置的 `GITHUB_TOKEN` 登录（已声明 `packages: write` 权限）。如果仓库是私有的，镜像权限跟随仓库可见性。

本地开发可选（非必需）：

```bash
make test    # 运行单元测试
make build   # 本地构建单个二进制
```

## 安全须知

1. 管理界面默认密码 `portguard` 必须修改；建议不要暴露到公网
2. 爱快 API 使用管理员密码认证，建议创建专用账号并定期更换密码
3. 白名单默认包含全部私网段，防止误封内网设备；如有公网 IP 需要豁免，加入 `whitelist`
4. `ban_mode=none` 可切换为只告警不封禁，用于观察阈值是否合理

## 已知限制

- 爱快不同固件版本的 API 字段名存在差异。封禁接口通过多形态探测自动适配；如果全部失败，请在 Web 界面手动指定 `ban_mode`，或提交 Issue 附上固件版本和 API 返回内容。
- `conn_poll_enabled` 依赖固件是否提供连接表接口（`func_name` 默认 `monitor_conn`），可在配置中修改。
- 爱快官方 Docker 应用禁止宿主网络（`network_mode: host`），因此通过应用市场 ipkg 部署时 AF_PACKET 抓包不可用（已默认关闭）；检测由连接表轮询 + Syslog 承担。只有在普通 Linux 主机上自建并改用宿主网络时，抓包才可用。

## License

MIT

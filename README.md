# Port Guard

> 部署在爱快（iKuai）路由器上的串联转发防护工具。爱快把外网端口映射到本应用，由代理转发到内网服务；所有连接必经代理，检测引擎按源 IP 统计行为，命中规则即在 accept 阶段当场断开并封禁，到期自动解封。封禁时长、阈值、白名单全部可配置（默认封禁 **30 分钟**）。
>
> 提供两种部署方式：**爱快应用市场 Docker 应用（.ipkg）** 与 **Docker 镜像（GHCR）**，均由 GitHub Actions 自动构建发布，无需本地编译。

## 为什么需要它

端口映射把内网服务暴露到公网后，会立刻成为扫描器的目标：SSH 爆破、Redis/MySQL 未授权访问探测、连接频率异常等。爱快自带的 ACL 和黑名单是静态规则，不会根据实时行为动态封禁。Port Guard 补上这一环：

- **串联代理**：爱快外网端口 → 本应用监听端口 → 内网服务，流量必经，在 accept 阶段按对端 IP 做判定（若爱快 DNAT 保留源地址，即为真实公网 IP）
- **本地即时封禁**：命中规则当场断开连接，来自被封 IP 的新连接直接拒绝，**不依赖爱快 API**（也就不受固件接口差异影响）
- **登录爆破防护**：接收群晖 / Windows / Ubuntu 转发的登录失败日志，同一 IP 失败 3 次即封禁
- **抑制误封**：私网地址、白名单 CIDR 一律不参与判定
- **日志自动清理**：事件日志与已解除的封禁历史默认保留 3 天，启动时立即清理并每 6 小时执行一次

## 检测原理

端口映射本质是 DNAT 放通规则，外部扫描映射端口时，这些连接在爱快眼里是"允许"的，不会出现在拦截日志里；爱快 V4 固件也不提供可用的连接表接口。因此 Port Guard 改用**串联代理**：把要防护的服务先经过本应用，流量自己送上门。

```
公网客户端 → 爱快外网端口 → port-guard 监听端口(22300-22349) → 内网服务
                                  ↑ 检测 + 封禁在这里发生
```

代理在 accept 阶段依次判定：白名单放行 → 已封禁 IP 直接拒绝 → 送检测引擎判定（命中则当场断开）→ 转发到内网后端。

检测引擎按滑动窗口（默认 60 秒）统计，命中以下任一规则即告警并封禁：

- `conn_rate`：同一 IP 新建连接数 ≥ 60
- `port_scan`：同一 IP 探测不同端口数 ≥ 8
- `syn_flood` / `udp_flood`：保留的阈值规则（代理为 TCP 转发，主要用前两条）
- `login_brute`：同一 IP 登录失败 ≥ 3 次（独立 5 分钟窗口，来自 NAS / Windows / Ubuntu 日志）

同一 IP 告警后有 300 秒冷却期，避免重复封禁。所有阈值都可在 Web 界面调整。登录爆破的日志转发步骤见 [LOG-FORWARDING.md](docs/LOG-FORWARDING.md)。

> **只代理需要防护的端口**：SSH、RDP、MySQL、NAS 管理页等敏感端口走代理；群晖下载这类大流量端口保持爱快直连。代理是串行单点，本应用故障时走它的服务会中断。

## 快速开始

两种部署方式任选其一，都从 [GitHub Releases](https://github.com/zxkbazinga/port-guard/releases) 获取成品，无需本地构建。

### 方式 A：爱快应用市场 Docker 应用（.ipkg，推荐）

前提：爱快已安装并启用 **Docker 插件**。进入 **扩展服务 → 应用市场 → 本地安装**，上传 Release 中的 `port-guard-<版本>-ikuai.ipkg`。

ipkg 是 Docker 类型应用（`manifest.json` 中 `type: "1"`），安装后自动从 `ghcr.io/zxkbazinga/port-guard:<版本>` 拉取镜像并创建容器。爱快 Docker 插件**禁止宿主网络**，容器用标准 bridge 网络 + 端口映射：Web 管理端口（默认 5657）、Syslog 接收端口（UDP 5140）、代理监听端口池（22300–22349）。这些端口都可在应用配置页查看。

安装后点击应用详情页的「打开」进入 Web 管理界面（默认 `http://<爱快LAN-IP>:5657`，默认账号 `admin` / `portguard`）。**登录后请立即在「系统配置 → 管理界面」修改密码。**

### 方式 B：Docker 镜像（GHCR）

```bash
docker pull ghcr.io/zxkbazinga/port-guard:latest
docker compose up -d
```

Web 界面监听 **5657**、Syslog 监听 UDP **5140**、代理池 **22300–22349**。

### 配置转发代理

1. **系统配置 → 转发代理**：勾选「启用转发代理」，按需调整端口池范围（须在容器已映射的 22300–22349 内），保存。
2. **转发代理 → 添加转发规则**：填监听端口（如 `22300`）、后端内网 IP（如 `192.168.1.10`）、后端端口（如 `22`）、备注。
3. **爱快 → 端口映射**：把要防护的那个服务的映射「内网目标」改成 `本应用IP : 监听端口`，**外网端口保持不变**。例如原来 `公网2222 → 192.168.1.10:22`，改成 `公网2222 → 本应用IP:22300`。
4. 用公网侧访问验证：概览页「代理转发连接」计数增长、转发代理页「最近连接」出现记录即链路打通。

> **配置持久化**：Web 界面保存的值优先于环境变量。ipkg 的 `environment` 中的 `PG_*` 仅作首次启动初始值，容器重启不会覆盖你在 Web 页面保存的配置。

## 配置项说明

| 配置 | 默认值 | 说明 |
|---|---|---|
| `proxy_enabled` | false | 启用串联转发代理 |
| `proxy_port_start` / `proxy_port_end` | 22300 / 22349 | 代理监听端口池（须在容器映射范围内） |
| `ban_duration_minutes` | 30 | 封禁时长（分钟） |
| `whitelist` | 私网段 | 逗号分隔的 CIDR，永不封禁 |
| `ignore_private_ips` | true | 忽略 RFC1918 私网地址 |
| `window_seconds` | 60 | 统计窗口 |
| `conn_rate_threshold` | 60 | 连接频率阈值 |
| `port_scan_threshold` | 8 | 端口扫描阈值（不同端口数） |
| `syn_flood_threshold` | 30 | SYN Flood 阈值 |
| `udp_flood_threshold` | 80 | UDP Flood 阈值 |
| `alert_cooldown_seconds` | 300 | 同一 IP 告警冷却时间 |
| `syslog_port` | 5140 | 登录失败日志接收端口（UDP） |
| `login_fail_enabled` / `threshold` / `window` | true / 3 / 300 | 登录爆破防护 |
| `event_retention_days` | 3 | 事件与封禁历史保留天数 |

所有配置均可通过 Web 界面修改，无需重启容器，且会持久化到 SQLite（容器重启不丢）。环境变量仅用于首次初始化，一旦某项在 Web 保存过，就以保存值为准。

## HTTP API

管理界面之外提供 JSON API（需先通过 `/login` 获取会话 Cookie）：

```
GET    /api/status          运行状态、代理与引擎统计
GET    /api/events?limit=100&type=attack   事件日志
GET    /api/bans            封禁列表
GET    /api/config          当前配置
POST   /api/config          更新配置（JSON）
GET    /api/forwards        转发规则列表
POST   /api/forwards        添加转发规则 {"listen_port":22300,"backend_ip":"192.168.1.10","backend_port":22,"label":"NAS SSH"}
POST   /api/forwards/{id}/toggle   启停规则
DELETE /api/forwards/{id}   删除规则
POST   /api/ban             手工封禁 {"ip":"1.2.3.4","minutes":30,"reason":"..."}
POST   /api/unban           手工解封 {"ip":"1.2.3.4"}
GET    /health              健康检查
```

## 技术栈与体积

- **Go 1.26+**，纯静态编译，无 CGO
- **SQLite**：`modernc.org/sqlite`（纯 Go 驱动）
- **Web**：标准库 `net/http` + `html/template`，模板与静态资源 `embed` 进二进制
- **转发**：标准库 `net` 双向 TCP 转发，`SetNoDelay` + 半关闭
- 静态二进制约 15MB，ipkg 包仅数 KB（只含 compose 与配置，镜像从 GHCR 拉取），Docker 镜像约 39MB，运行内存 15–30MB
- 支持 `linux/amd64` 与 `linux/arm64`

## 自动构建与发布（GitHub Actions）

| Workflow | 触发时机 | 作用 |
|---|---|---|
| `.github/workflows/ci.yml` | push / PR 到 main | 格式检查、go vet、单元测试（含 race）、双架构交叉编译、ipkg 配置校验 |
| `.github/workflows/release.yml` | 推送 `v*` 标签（如 `v1.0.0`） | 构建多架构 GHCR 镜像 + ipkg 包 + 独立二进制，创建 GitHub Release |

```bash
git tag v1.0.0
git push origin v1.0.0
```

推送后自动构建并发布 GHCR 镜像、ipkg 包、独立二进制，并创建 GitHub Release。

本地开发可选：

```bash
make test    # 运行单元测试
make build   # 本地构建单个二进制
```

## 安全须知

1. 管理界面默认密码 `portguard` 必须修改；建议不要暴露到公网
2. 白名单默认包含全部私网段，防止误封内网设备；如有公网 IP 需要豁免，加入 `whitelist`
3. 代理是串行单点：只把敏感端口切到代理，大流量下载端口保持直连
4. 转发规则指向的后端请确保只监听内网，避免绕过代理直连

## 已知限制

- 代理为串行单点，本应用故障或重启时，切到代理的服务会短暂中断
- bridge 网络下容器只能监听 compose 预先映射的端口，因此代理监听端口必须在 22300–22349 范围内；要突破需改 `docker-compose.yaml` 并重装
- 后端服务看到的来源 IP 会变成容器 IP（代理是新发起的 TCP 连接）；后端访问日志不再反映真实公网 IP。若后端 Syslog 里的登录失败也记的是代理私网 IP，会被「忽略私网 IP」规则跳过，此场景请以代理层连接检测为准

## License

MIT

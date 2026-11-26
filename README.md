# Port Guard

> 部署在爱快（iKuai）路由器上的串联转发防护工具。爱快把外网端口映射到本应用，由代理转发到内网服务；所有连接必经代理，检测引擎按源 IP 统计行为，命中规则即在 accept 阶段当场断开并封禁，到期自动解封。封禁时长、阈值、白名单全部可配置（默认封禁 **30 分钟**）。
>
> 提供两种部署方式：**爱快应用市场 Docker 应用（.ipkg）** 与 **Docker 镜像（GHCR）**，均由 GitHub Actions 自动构建发布，无需本地编译。

## 为什么需要它

端口映射把内网服务暴露到公网后，会立刻成为扫描器的目标：SSH 爆破、Redis/MySQL 未授权访问探测、连接频率异常等。爱快自带的 ACL 和黑名单是静态规则，不会根据实时行为动态封禁。Port Guard 补上这一环：

- **串联代理**：爱快外网端口 → 本应用监听端口 → 内网服务，流量必经，在 accept 阶段按对端 IP 做判定（若爱快 DNAT 保留源地址，即为真实公网 IP）
- **可选 HTTPS 终结**：把证书和私钥放到本应用持久化目录，转发规则勾选「入口 HTTPS」后由 port-guard 完成 TLS 握手，再按配置转发到内网 HTTP 或 HTTPS 服务
- **来源地区限制**：转发端口可设为仅允许中国大陆，或中国大陆 + 中国香港 + 中国澳门 + 中国台湾；基于编译进二进制的 APNIC 分配表离线判断，境外公网 IP 在 accept 阶段直接拒绝**并拉黑**（本地即时生效 + 写入封禁记录，封禁管理页可见，默认 30 分钟），管理界面不受影响
- **日志带归属地**：转发日志新增归属地列，基于离线 RIR 分配表显示来源国家/地区（如「美国」「印度」「中国大陆」），私网显示「内网」，无需联网查询
- **本地即时封禁**：命中规则当场断开连接，来自被封 IP 的新连接直接拒绝，**不依赖爱快 API**（也就不受固件接口差异影响）；容器重启后未到期的活跃封禁会从数据库自动恢复，不会给被封 IP 重新连入的机会
- **钉钉通知**：新 IP 被封禁时向钉钉群机器人推送提醒（含来源 IP、归属地、规则、端口、时长），支持加签与关键词校验
- **手动检查更新**：概览页显示当前版本，点「检查更新」才请求 GitHub 查询最新 Release，显示版本对比与更新说明；不自动联网，查询失败不影响任何功能
- **登录爆破防护**：接收群晖 / Windows / Ubuntu 转发的登录失败日志，同一 IP 失败 3 次即封禁
- **抑制误封**：私网地址、白名单 CIDR 一律不参与判定
- **日志自动清理**：事件日志与已解除的封禁历史默认保留 3 天，启动时立即清理并每 6 小时执行一次

## 检测原理

端口映射本质是 DNAT 放通规则，外部扫描映射端口时，这些连接在爱快眼里是"允许"的，不会出现在拦截日志里；爱快 V4 固件也不提供可用的连接表接口。因此 Port Guard 改用**串联代理**：把要防护的服务先经过本应用，流量自己送上门。

```
公网客户端 → 爱快外网端口 → port-guard 监听端口(22300-22349) → 内网服务
                                  ↑ 检测 + 封禁在这里发生
```

代理在 accept 阶段依次判定：白名单放行 → 地区限制（境外 IP 拒绝并拉黑）→ 已封禁 IP 直接拒绝 → 送检测引擎判定（命中则当场断开）→ 转发到内网后端。

检测引擎按滑动窗口（默认 60 秒）统计，命中以下任一规则即告警并封禁：

- `conn_rate`：同一 IP 新建连接数 ≥ 60
- `port_scan`：同一 IP 探测不同端口数 ≥ 8
- `short_conn`：同一 IP 在 3 秒内传输不足 8KB 就断开的"低流量短连接" ≥ 8 次。这是四层代理能抓慢速爆破的关键信号——密码爆破每次只交换认证包便断开，而正常 SSH/MySQL/RDP 登录成功后会有持续流量或长连接保持，不会被误伤。
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

1. **系统配置 → 转发代理**：勾选「启用转发代理」，按需调整端口池范围（须在容器已映射的 22300–22349 内），把「转发来源地区限制」选为「仅中国大陆」（默认），保存。若需要放行中国香港/中国澳门/中国台湾来源，改成「中国大陆 + 中国香港 + 中国澳门 + 中国台湾」；需要放行所有来源就选「不限制」。白名单 CIDR 与私网地址始终放行，管理界面 5657 不受此限制。
2. **转发代理 → 添加转发规则**：填监听端口（如 `22300`）、后端内网 IP（如 `192.168.1.10`）、后端端口（如 `22`）、备注。
3. **爱快 → 端口映射**：把要防护的那个服务的映射「内网目标」改成 `本应用IP : 监听端口`，**外网端口保持不变**。例如原来 `公网2222 → 192.168.1.10:22`，改成 `公网2222 → 本应用IP:22300`。
4. 用公网侧访问验证：概览页「代理转发连接」计数增长、转发代理页下方「转发日志」出现记录即链路打通。日志框保留最近 1000 条（内存中，重启后清空），每 3 秒自动刷新，最新记录在底部并默认自动滚动跟随；往上翻看历史会暂停跟随，取消勾选「自动滚动」可一直停在历史位置。连接一建立就写入（长连接显示「连接中」，结束后回填耗时），每条包含时间、来源 IP、归属地、监听端口、后端、判定动作和耗时，方便确认公网访问是否真的到达代理。

> **地区数据更新**：`internal/geoip/data/blocks.txt`（地区限制）由 APNIC `delegated-apnic-latest` 生成；`internal/geoip/data/countries.txt`（日志归属地）由 ARIN/APNIC/RIPE/AFRINIC/LACNIC 五大 RIR 的 `delegated-*-extended-latest` 合并生成。两份数据随二进制编译，运行时不访问外网。归属地显示的是 IP 段的 RIR 注册国家，少数转售/Anycast 地址的实际使用地可能不同。

> **配置持久化**：Web 界面保存的值优先于环境变量。ipkg 的 `environment` 中的 `PG_*` 仅作首次启动初始值，容器重启不会覆盖你在 Web 页面保存的配置。

### 钉钉封禁通知（可选）

有**新 IP 被封禁**时（自动检测、地区限制或手工封禁）推送一条 Markdown 提醒，包含来源 IP、归属地、触发规则、目标端口、封禁时长和时间。重复告警、保护名单 IP、到期解封不会重复推送；通知异步发送，钉钉接口异常不影响封禁。

1. 在钉钉群里添加「自定义机器人」，安全设置至少配一项：加签（复制 SEC 密钥）或关键词（记下任一关键词），两者都配也可以。
2. 进入 **系统配置 → 钉钉通知**：勾选启用，填入 Webhook 地址、SEC 密钥和/或关键词，保存。
3. 点「发送测试消息」确认群里能收到。输入框显示 `********` 表示已保存的凭据保持不变，不用重新填写。

> 通知队列最多缓存 256 条，超出后丢弃并写日志；单条请求 5 秒超时。Webhook 地址含 `access_token`，与 API Token 一样属于敏感信息，请勿外传。

### 检查更新

概览页顶部显示当前版本，点「检查更新」会向 GitHub Releases API 查询最新版本，显示版本对比、Release 链接和更新说明。**只在点击时请求一次**（8 秒超时），不做后台轮询、不参与防护判定；容器无法访问 `api.github.com` 时会提示检查失败，不影响系统运行。需要手动升级时按「安装/升级」章节拉取新镜像或 ipkg 包。

> 内部构建（`dev`）或自定义版本不会误报"有新版本"，只有能解析出 `x.y.z` 的版本号才参与比较。

### HTTPS 证书终结（可选）

如果你希望域名证书放在 port-guard 上，而不是放在网关/群晖上，按下面配置：

**方式一：Gately 自动推送（推荐，全自动）**

如果证书由 Gately 申请/续期，用它的「自动部署 → 复制后执行」在证书更新后自动推送：

1. 进入 port-guard **系统配置 → HTTPS 证书 → 自动推送**，点「生成随机 Token」并**保存**。
2. 点「复制推送命令」，把命令填到 Gately 自动部署目标的「复制后执行」框：

   ```sh
   curl -fsS -X POST \
     -H "Authorization: Bearer YOUR_API_TOKEN" \
     -F "cert=@$certFile" \
     -F "key=@$keyFile" \
     http://PORT_GUARD_IP:5657/api/certs/push
   ```

   Gately 提供的 `$certFile` / `$keyFile` 变量指向刚复制好的证书与私钥。`YOUR_API_TOKEN` 换成上一步的 Token，`PORT_GUARD_IP` 换成能访问本应用的地址（Gately 在容器内就填容器可达 IP）。

3. 证书签发/续期后 Gately 自动推送，port-guard 校验匹配后原子写入并重载监听器，与页面上传效果一致。免 SSH/SFTP、免登录、免手动干预。

对应接口：`POST /api/certs/push`，支持 Bearer Token 或 `X-API-Token` 请求头，字段可用 multipart 文件 `cert` / `key`（也兼容 `cert_pem` / `key_pem` 文本字段）。未配置 API Token 时该接口拒绝访问。

**方式二：页面手动上传**

进入 **系统配置 → HTTPS 证书（代理 TLS 终结）**，直接选择证书链 PEM 和私钥 PEM，点「上传证书并生效」。爱快 SSH 没有完整 SFTP 子系统时也能用；文件会写入应用持久化目录。容器内默认读取：

   ```
   /data/certs/fullchain.pem
   /data/certs/privkey.pem
   ```

   也可以通过爱快 Web 文件管理把文件放到应用数据目录的 `certs/` 子目录，但页面上传最省事。不要放到容器临时文件系统。

**配置路径**：如果修改了默认路径，进入同一模块修改后保存；默认路径不用改。写入后会自动触发代理重新加载，无需重启容器。

3. **添加转发规则**：在 **转发代理** 添加规则，「服务类型」选 **HTTPS 网站**：

   ```
   监听端口：22301
   后端内网 IP：网关的 LAN IP
   后端端口：443 或网关 HTTP 端口
   服务类型：HTTPS 网站
   ```

   内网服务收明文就不勾额外选项；内网本身就是 HTTPS（哪怕只有 IP + 自签证书）就勾上「忽略 SSL 证书」，port-guard 会用 HTTPS 连后端且不校验证书，无需域名或 SNI。

> **哪些服务能用 port-guard 的证书？只有 HTTPS 网站**（浏览器 `https://` 访问的网页服务）。MySQL(3306)、Windows 远程桌面 RDP(3389)、SSH(22)、群晖 DSM 的 HTTP(5000) 用的是各自独立的加密协议，客户端不会跟 port-guard 做标准 TLS 握手——这些服务请在「服务类型」选 **普通服务**，由 port-guard 原样透传，加密由数据库/远程桌面/SSH 服务端自己负责。给它们选 HTTPS 会导致握手失败。

4. **爱快端口映射**：域名 443 场景把 **TCP 443** 指向 `本应用IP:22301`。不要把 UDP 443 指到这个 TCP 监听口；UDP 443（QUIC）应直连原网关或关闭。

5. **验证**：浏览器访问 `https://域名`，转发日志应出现该连接的记录；若证书路径或内容错误，日志动作会显示 `TLS握手失败`，同时容器日志会打印具体错误。

> 当前是**单证书**终结：所有启用入口 HTTPS 的规则共用同一份证书。如果要按多个域名自动选择不同证书，需要后续增加 SNI 证书表。

## 配置项说明

| 配置 | 默认值 | 说明 |
|---|---|---|
| `proxy_enabled` | false | 启用串联转发代理 |
| `proxy_port_start` / `proxy_port_end` | 22300 / 22349 | 代理监听端口池（须在容器映射范围内） |
| `geo_mode` | `cn` | 转发来源地区限制：`off` 不限制 / `cn` 仅中国大陆 / `cn_all` 中国大陆 + 中国香港 + 中国澳门 + 中国台湾；只作用于转发端口 |
| `api_token` | 空 | 脚本推送证书用的 Bearer Token，留空则禁用 Token 认证 |
| `tls_cert_file` | `/data/certs/fullchain.pem` | 入口 HTTPS 终结使用的证书链 PEM 路径 |
| `tls_key_file` | `/data/certs/privkey.pem` | 入口 HTTPS 终结使用的私钥 PEM 路径 |
| `ban_duration_minutes` | 30 | 封禁时长（分钟） |
| `whitelist` | 私网段 | 逗号分隔的 CIDR，永不封禁 |
| `ignore_private_ips` | true | 忽略 RFC1918 私网地址 |
| `window_seconds` | 60 | 统计窗口 |
| `conn_rate_threshold` | 60 | 连接频率阈值 |
| `short_conn_threshold` | 8 | 短连接爆破阈值（窗口内低流量短连接次数） |
| `port_scan_threshold` | 8 | 端口扫描阈值（不同端口数） |
| `alert_cooldown_seconds` | 300 | 同一 IP 告警冷却时间 |
| `syslog_port` | 5140 | 登录失败日志接收端口（UDP） |
| `login_fail_enabled` / `threshold` / `window` | true / 3 / 300 | 登录爆破防护 |
| `event_retention_days` | 3 | 事件与封禁历史保留天数 |
| `dingtalk_enabled` | false | 新封禁 IP 时发送钉钉通知 |
| `dingtalk_webhook` | 空 | 钉钉机器人 Webhook 完整地址（含 access_token） |
| `dingtalk_secret` | 空 | 加签机器人的 SEC 密钥，留空表示未开启加签 |
| `dingtalk_keyword` | 空 | 关键词安全设置的关键词，发送时自动附在消息开头 |

所有配置均可通过 Web 界面修改，无需重启容器，且会持久化到 SQLite（容器重启不丢）。环境变量仅用于首次初始化，一旦某项在 Web 保存过，就以保存值为准。

## HTTP API

管理界面之外提供 JSON API（需先通过 `/login` 获取会话 Cookie）：

```
GET    /api/status          运行状态、代理与引擎统计
GET    /api/events?limit=100&type=attack   事件日志
GET    /api/bans            封禁列表
GET    /api/config          当前配置
POST   /api/config          更新配置（JSON）
GET    /api/certs/status    证书状态与到期时间
POST   /api/certs           上传证书 {"cert_pem":"-----BEGIN CERTIFICATE-----...","key_pem":"-----BEGIN PRIVATE KEY-----..."}
POST   /api/certs/push      脚本推送证书（multipart: cert/key 文件，需 Bearer Token）
POST   /api/notify/test     同步发送一条钉钉测试消息（需先保存并启用通知）
GET    /api/forwards        转发规则列表
POST   /api/forwards        添加转发规则 {"listen_port":22300,"backend_ip":"192.168.1.10","backend_port":22,"label":"NAS SSH"}；HTTPS 终结可加 "listen_tls":true，"backend_tls":true（后端 HTTPS 且忽略证书校验）
POST   /api/forwards/{id}/toggle   启停规则
DELETE /api/forwards/{id}   删除规则
GET    /api/forwards/logs?limit=1000   转发日志（内存，最多 1000 条）
POST   /api/forwards/logs/clear        清空转发日志
POST   /api/ban             手工封禁 {"ip":"1.2.3.4","minutes":30,"reason":"..."}
POST   /api/unban           手工解封 {"ip":"1.2.3.4"}
GET    /health              健康检查
```

## 技术栈与体积

- **Go 1.26+**，纯静态编译，无 CGO
- **SQLite**：`modernc.org/sqlite`（纯 Go 驱动）
- **Web**：标准库 `net/http` + `html/template`，模板与静态资源 `embed` 进二进制
- **转发**：标准库 `net` 双向 TCP 转发，`SetNoDelay` + 半关闭；可选 `crypto/tls` 入口终结与后端重加密
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
- HTTPS 终结当前共用一份证书，不支持同一监听端口按 SNI 自动选择多张证书
- 启用「后端 HTTPS」时会重新发起 TLS 连接；如果后端是自签证书且不在系统信任链内，当前会校验证书失败，请优先让后端使用受信任证书或不要勾选后端 HTTPS

## License

MIT

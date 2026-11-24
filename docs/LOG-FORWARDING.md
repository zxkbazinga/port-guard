# 服务器登录失败日志转发指南

Port Guard 的「登录爆破防护」需要接收来自 NAS / Windows / Ubuntu 的登录失败日志。本文教你把这三台机器的日志发送到 Port Guard 的 **Syslog 端口（默认 5140/UDP）**。

## 前置条件

1. Port Guard 已运行，且「系统配置 → 检测源 → 接收爱快 Syslog」已勾选（同一端口也接收服务器日志）。
2. Port Guard 所在主机能从你的服务器访问到（同一内网，或能路由到）。记下这台主机的内网 IP，下面记作 `<PG_IP>`。
3. 「系统配置 → 登录爆破防护」里已启用，阈值默认 3 次、窗口 300 秒，可按需调整。

> 说明：这些日志走 UDP，是内网传输，不经过公网，不会暴露你的登录信息。Port Guard 只提取「来源 IP + 失败事件」，不存储密码。

---

## 一、Ubuntu / Debian（sshd 登录失败）

Ubuntu 用 `rsyslog` 转发认证日志，最简单。

### 1. 编辑 rsyslog 配置

新建配置文件：

```bash
sudo nano /etc/rsyslog.d/99-portguard.conf
```

写入以下内容（把 `<PG_IP>` 换成实际 IP）：

```
# 转发 sshd 认证失败日志到 Port Guard
authpriv.*  action(type="omfwd"
                   target="<PG_IP>"
                   port="5140"
                   protocol="udp"
                   action.resumeRetryCount="-1")
```

> `authpriv.*` 会转发所有认证日志（含成功登录），Port Guard 只认失败关键词，成功日志会被自动忽略，不影响。

### 2. 重启 rsyslog

```bash
sudo systemctl restart rsyslog
```

### 3. 测试

在另一台机器上故意用错密码 ssh 登录这台 Ubuntu 三次，然后到 Port Guard 的「事件日志」页，应出现「登录爆破行为」告警，来源 IP 是那台测试机。

> 如果你的系统用 `systemd-journald` 而非 rsyslog（较新版本），先确认 `/var/log/auth.log` 存在。若不存在，安装 rsyslog：`sudo apt install rsyslog` 并启用。

---

## 二、Windows Server（RDP / 远程登录失败）

Windows 本身不发 syslog，需要装一个轻量转发工具。推荐 **NXLog Community Edition**（免费）。

### 1. 开启登录失败审核

以管理员身份打开 PowerShell，执行：

```powershell
auditpol /set /subcategory:"Logon" /failure:enable
```

这会让 Windows 记录事件 ID **4625**（登录失败）。

### 2. 安装 NXLog CE

从 NXLog 官网下载 Community Edition：https://nxlog.co/products/nxlog-community-edition
下载 Windows MSI 安装包，一路默认安装。

### 3. 配置 NXLog

打开配置文件 `C:\Program Files (x86)\nxlog\conf\nxlog.conf`（或安装目录下的 `conf\nxlog.conf`），用以下内容替换（把 `<PG_IP>` 换成实际 IP）：

```
define ROOT C:\Program Files (x86)\nxlog

Moduledir %ROOT%\modules
CacheDir  %ROOT%\data
Pidfile   %ROOT%\data\nxlog.pid
SpoolDir  %ROOT%\data
LogFile   %ROOT%\data\nxlog.log

<Extension syslog>
    Module xm_syslog
</Extension>

<Input eventlog>
    Module im_msvistalog
    # 只采集登录失败事件 4625
    Query <QueryList>\
            <Query Id="0">\
              <Select Path="Security">*[System[(EventID=4625)]]</Select>\
            </Query>\
          </QueryList>
    # 把多行消息压成单行，便于 syslog 传输
    Exec $Message =~ s/(\t|\R)/ /g;
</Input>

<Output out>
    Module om_udp
    Host <PG_IP>
    Port 5140
    # 转成 BSD syslog 格式，Port Guard 能正确解析
    Exec to_syslog_bsd();
</Output>

<Route route>
    Path eventlog => out;
</Route>
```

### 4. 重启 NXLog 服务

```powershell
Restart-Service nxlog
```

### 5. 测试

用错误密码远程桌面登录这台 Windows 三次，到 Port Guard「事件日志」页查看是否出现「登录爆破行为」。

> 如果事件日志里 IP 提取不对，可检查 `C:\Program Files (x86)\nxlog\data\nxlog.log` 是否有发送错误。Windows 4625 事件里来源 IP 字段是 `Source Network Address`，Port Guard 已支持识别。

---

## 三、群晖 NAS（DSM 登录失败）

群晖原生支持远程 syslog，最简单，无需装工具。

1. 打开 **控制面板 → 日志中心**（Log Center）
2. 进入 **日志发送** 或 **远程日志服务器** 标签
3. 勾选「发送到远程日志服务器」
4. 填写：
   - 服务器地址：`<PG_IP>`
   - 端口：`5140`
   - 协议：UDP
5. 日志类型勾选「系统」和「安全」（登录失败在安全日志里）
6. 点击「应用」

> 群晖的登录失败日志关键词（「登录失败」「密码错误」等）Port Guard 已支持，实测可用。

---

## 常见问题

**Q：配置完没反应？**
- 先确认网络连通：在服务器上 `ping <PG_IP>` 能通
- 确认 Port Guard 的 5140/UDP 端口没被防火墙挡住（Docker 用 host 网络、ipkg 原生应用默认都监听 `0.0.0.0:5140`）
- 到 Port Guard 概览页看「Syslog 接收」的 messages 计数是否在增长——增长说明日志送到了

**Q：会不会把正常日志也当攻击？**
不会。只有「同一 IP 在窗口内登录失败达到阈值」（默认 5 分钟内 3 次）才会封禁，偶尔输错一两次密码不会触发。

**Q：UDP 日志会不会丢？**
局域网内 UDP 基本不会丢。即便偶尔丢一两条，也不影响计数判定（少算一两次而已）。

**Q：能只封禁登录失败，不开端口扫描检测吗？**
可以。在「系统配置 → 检测源」里取消「抓包检测」和「轮询爱快连接表」，只保留 Syslog 和登录爆破，就只按日志判定。

// Package config 管理运行时配置。配置保存在 SQLite 中，Web 界面修改后即时生效。
package config

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/zxkbazinga/port-guard/internal/store"
)

// Config 是运行时配置的强类型视图。
type Config struct {
	mu sync.RWMutex
	s  *store.Store
	c  values
}

type values struct {
	// Web
	WebUsername     string `json:"web_username"`
	WebPasswordHash string `json:"web_password_hash"`
	WebSessionHours int    `json:"web_session_hours"`
	// 爱快
	IKuaiHost     string `json:"ikuai_host"`
	IKuaiPort     int    `json:"ikuai_port"`
	IKuaiUsername string `json:"ikuai_username"`
	IKuaiPassword string `json:"ikuai_password"`
	IKuaiSSL      bool   `json:"ikuai_ssl"`
	IKuaiTimeout  int    `json:"ikuai_timeout"`
	// 封禁
	BanMode            string `json:"ban_mode"` // auto | blacklist | acl | none
	BanDurationMinutes int    `json:"ban_duration_minutes"`
	Whitelist          string `json:"whitelist"`
	IgnorePrivateIPs   bool   `json:"ignore_private_ips"`
	// 检测开关
	DetectionEnabled bool   `json:"detection_enabled"`
	SnifferEnabled   bool   `json:"sniffer_enabled"`
	SnifferIface     string `json:"sniffer_iface"`
	SyslogEnabled    bool   `json:"syslog_enabled"`
	SyslogPort       int    `json:"syslog_port"`
	ConnPollEnabled  bool   `json:"conn_poll_enabled"`
	ConnPollInterval int    `json:"conn_poll_interval"`
	ConnFuncName     string `json:"conn_func_name"`
	PortRefresh      bool   `json:"port_refresh_enabled"`
	PortRefreshInt   int    `json:"port_refresh_interval"`
	// 阈值
	WindowSeconds      int `json:"window_seconds"`
	SynFloodThreshold  int `json:"syn_flood_threshold"`
	PortScanThreshold  int `json:"port_scan_threshold"`
	ConnRateThreshold  int `json:"conn_rate_threshold"`
	UDPFloodThreshold  int `json:"udp_flood_threshold"`
	AlertCooldown      int `json:"alert_cooldown_seconds"`
	EventRetentionDays int `json:"event_retention_days"`
	// 登录爆破检测（来自 NAS / Windows / Ubuntu 转发的安全日志）
	LoginFailEnabled   bool `json:"login_fail_enabled"`
	LoginFailThreshold int  `json:"login_fail_threshold"`
	LoginFailWindow    int  `json:"login_fail_window_seconds"`
	// 诱饵端口：由爱快 DNAT 把不用的端口转到本容器，连上来即视为扫描
	DecoyEnabled    bool   `json:"decoy_enabled"`
	DecoyPorts      string `json:"decoy_ports"`
	DecoyThreshold  int    `json:"decoy_threshold"`
	DecoyWindow     int    `json:"decoy_window_seconds"`
	DecoyBanEnabled bool   `json:"decoy_ban_enabled"`
	DecoyBanMinutes int    `json:"decoy_ban_minutes"`
	// 串联代理模式：爱快把外网端口映射到本应用，由代理转发到内网服务
	ProxyEnabled   bool `json:"proxy_enabled"`
	ProxyPortStart int  `json:"proxy_port_start"` // 代理监听端口池起始（须在 compose 暴露范围内）
	ProxyPortEnd   int  `json:"proxy_port_end"`   // 代理监听端口池结束
}

func defaults() values {
	return values{
		WebUsername: "admin", WebPasswordHash: "$2y$default$portguard", WebSessionHours: 12,
		IKuaiHost: "192.168.1.1", IKuaiPort: 80, IKuaiUsername: "admin", IKuaiTimeout: 5,
		BanMode: "auto", BanDurationMinutes: 30,
		Whitelist:        "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16",
		IgnorePrivateIPs: true,
		DetectionEnabled: true, SnifferEnabled: true, SnifferIface: "any",
		SyslogEnabled: true, SyslogPort: 5140,
		ConnPollEnabled: false, ConnPollInterval: 30, ConnFuncName: "monitor_conn",
		PortRefresh: true, PortRefreshInt: 300,
		WindowSeconds: 60, SynFloodThreshold: 30, PortScanThreshold: 8,
		ConnRateThreshold: 60, UDPFloodThreshold: 80, AlertCooldown: 300,
		EventRetentionDays: 3,
		LoginFailEnabled:   true, LoginFailThreshold: 3, LoginFailWindow: 300,
		// 默认关闭；ipkg bridge 网络只暴露 22200-22203 四个容器端口，需在爱快做 DNAT
		DecoyEnabled: false, DecoyPorts: "22200,22201,22202,22203", DecoyThreshold: 2, DecoyWindow: 60,
		DecoyBanEnabled: false, DecoyBanMinutes: 1,
		ProxyEnabled: false, ProxyPortStart: ProxyPortPhysicalMin, ProxyPortEnd: ProxyPortPhysicalMax,
	}
}

// 代理监听端口池的物理边界：必须与 ikuai-support/port-guard/app/docker-compose.yaml
// 中 ${HOST_IP}:22300-22349:22300-22349/tcp 暴露的范围一致。bridge 网络下容器
// 只能监听已暴露端口，配置页可在此范围内调整实际使用的起止端口。
const (
	ProxyPortPhysicalMin = 22300
	ProxyPortPhysicalMax = 22349
)

// New 加载配置。数据库中缺失的项使用默认值，并应用环境变量覆盖。
func New(s *store.Store) (*Config, error) {
	c := &Config{s: s, c: defaults()}
	stored, err := s.AllConfig()
	if err != nil {
		return nil, err
	}
	for key, raw := range stored {
		apply(&c.c, key, raw)
	}
	c.applyEnv(stored)
	// 阈值兜底，防止配置错误导致所有流量都被判定为攻击
	c.normalize()
	return c, nil
}

func apply(v *values, key string, raw json.RawMessage) {
	switch key {
	case "web_username":
		get(raw, &v.WebUsername)
	case "web_password_hash":
		get(raw, &v.WebPasswordHash)
	case "web_session_hours":
		get(raw, &v.WebSessionHours)
	case "ikuai_host":
		get(raw, &v.IKuaiHost)
	case "ikuai_port":
		get(raw, &v.IKuaiPort)
	case "ikuai_username":
		get(raw, &v.IKuaiUsername)
	case "ikuai_password":
		get(raw, &v.IKuaiPassword)
	case "ikuai_ssl":
		get(raw, &v.IKuaiSSL)
	case "ikuai_timeout":
		get(raw, &v.IKuaiTimeout)
	case "ban_mode":
		get(raw, &v.BanMode)
	case "ban_duration_minutes":
		get(raw, &v.BanDurationMinutes)
	case "whitelist":
		get(raw, &v.Whitelist)
	case "ignore_private_ips":
		get(raw, &v.IgnorePrivateIPs)
	case "detection_enabled":
		get(raw, &v.DetectionEnabled)
	case "sniffer_enabled":
		get(raw, &v.SnifferEnabled)
	case "sniffer_iface":
		get(raw, &v.SnifferIface)
	case "syslog_enabled":
		get(raw, &v.SyslogEnabled)
	case "syslog_port":
		get(raw, &v.SyslogPort)
	case "conn_poll_enabled":
		get(raw, &v.ConnPollEnabled)
	case "conn_poll_interval":
		get(raw, &v.ConnPollInterval)
	case "conn_func_name":
		get(raw, &v.ConnFuncName)
	case "port_refresh_enabled":
		get(raw, &v.PortRefresh)
	case "port_refresh_interval":
		get(raw, &v.PortRefreshInt)
	case "window_seconds":
		get(raw, &v.WindowSeconds)
	case "syn_flood_threshold":
		get(raw, &v.SynFloodThreshold)
	case "port_scan_threshold":
		get(raw, &v.PortScanThreshold)
	case "conn_rate_threshold":
		get(raw, &v.ConnRateThreshold)
	case "udp_flood_threshold":
		get(raw, &v.UDPFloodThreshold)
	case "alert_cooldown_seconds":
		get(raw, &v.AlertCooldown)
	case "event_retention_days":
		get(raw, &v.EventRetentionDays)
	case "login_fail_enabled":
		get(raw, &v.LoginFailEnabled)
	case "login_fail_threshold":
		get(raw, &v.LoginFailThreshold)
	case "login_fail_window_seconds":
		get(raw, &v.LoginFailWindow)
	case "decoy_enabled":
		get(raw, &v.DecoyEnabled)
	case "decoy_ports":
		get(raw, &v.DecoyPorts)
	case "decoy_threshold":
		get(raw, &v.DecoyThreshold)
	case "decoy_window_seconds":
		get(raw, &v.DecoyWindow)
	case "decoy_ban_enabled":
		get(raw, &v.DecoyBanEnabled)
	case "decoy_ban_minutes":
		get(raw, &v.DecoyBanMinutes)
	case "proxy_enabled":
		get(raw, &v.ProxyEnabled)
	case "proxy_port_start":
		get(raw, &v.ProxyPortStart)
	case "proxy_port_end":
		get(raw, &v.ProxyPortEnd)
	}
}

func get(raw json.RawMessage, out any) {
	_ = json.Unmarshal(raw, out)
}

// applyEnv 用环境变量补充配置（爱快 ipkg 的 option.json → environment → PG_* 通道）。
// 关键：数据库中已显式保存过的键优先，环境变量只作为首次启动的初始值。
// 否则 ipkg 的 environment 里写死的 PG_IKUAI_HOST=127.0.0.1 等默认值会在每次
// 容器重启时覆盖用户在 Web 配置页保存的值，表现为「配置切换菜单/重启后就没了」。
func (c *Config) applyEnv(stored map[string]json.RawMessage) {
	// envKey 把 PG_* 环境变量映射到配置库键名；已在库中的键跳过环境变量。
	envKey := map[string]string{
		"PG_IKUAI_HOST": "ikuai_host", "PG_IKUAI_USERNAME": "ikuai_username",
		"PG_IKUAI_PASSWORD": "ikuai_password", "PG_WEB_USERNAME": "web_username",
		"PG_BAN_MODE": "ban_mode", "PG_WHITELIST": "whitelist",
		"PG_SNIFFER_IFACE": "sniffer_iface", "PG_CONN_FUNC_NAME": "conn_func_name",
		"PG_IKUAI_PORT": "ikuai_port", "PG_IKUAI_TIMEOUT": "ikuai_timeout",
		"PG_BAN_MINUTES": "ban_duration_minutes", "PG_SYSLOG_PORT": "syslog_port",
		"PG_CONN_POLL_INTERVAL": "conn_poll_interval", "PG_PORT_REFRESH_INTERVAL": "port_refresh_interval",
		"PG_WINDOW_SECONDS": "window_seconds", "PG_SYN_FLOOD_THRESHOLD": "syn_flood_threshold",
		"PG_PORT_SCAN_THRESHOLD": "port_scan_threshold", "PG_CONN_RATE_THRESHOLD": "conn_rate_threshold",
		"PG_UDP_FLOOD_THRESHOLD": "udp_flood_threshold", "PG_ALERT_COOLDOWN": "alert_cooldown_seconds",
		"PG_EVENT_RETENTION_DAYS": "event_retention_days", "PG_WEB_SESSION_HOURS": "web_session_hours",
		"PG_LOGIN_FAIL_THRESHOLD": "login_fail_threshold", "PG_LOGIN_FAIL_WINDOW": "login_fail_window_seconds",
		"PG_IKUAI_SSL": "ikuai_ssl", "PG_IGNORE_PRIVATE_IPS": "ignore_private_ips",
		"PG_DETECTION_ENABLED": "detection_enabled", "PG_SNIFFER_ENABLED": "sniffer_enabled",
		"PG_SYSLOG_ENABLED": "syslog_enabled", "PG_CONN_POLL_ENABLED": "conn_poll_enabled",
		"PG_PORT_REFRESH_ENABLED": "port_refresh_enabled", "PG_LOGIN_FAIL_ENABLED": "login_fail_enabled",
		"PG_DECOY_ENABLED":   "decoy_enabled",
		"PG_DECOY_PORTS":     "decoy_ports",
		"PG_DECOY_THRESHOLD": "decoy_threshold", "PG_DECOY_WINDOW": "decoy_window_seconds",
		"PG_DECOY_BAN_ENABLED": "decoy_ban_enabled",
		"PG_DECOY_BAN_MINUTES": "decoy_ban_minutes",
		"PG_PROXY_ENABLED":     "proxy_enabled",
		"PG_PROXY_PORT_START":  "proxy_port_start",
		"PG_PROXY_PORT_END":    "proxy_port_end",
	}
	use := func(envName string) bool {
		if v := os.Getenv(envName); v == "" {
			return false
		}
		key, ok := envKey[envName]
		if !ok {
			return true
		}
		_, saved := stored[key]
		return !saved // 库里已保存则跳过环境变量
	}
	envStr := map[string]*string{
		"PG_IKUAI_HOST":     &c.c.IKuaiHost,
		"PG_IKUAI_USERNAME": &c.c.IKuaiUsername,
		"PG_IKUAI_PASSWORD": &c.c.IKuaiPassword,
		"PG_WEB_USERNAME":   &c.c.WebUsername,
		"PG_BAN_MODE":       &c.c.BanMode,
		"PG_WHITELIST":      &c.c.Whitelist,
		"PG_SNIFFER_IFACE":  &c.c.SnifferIface,
		"PG_CONN_FUNC_NAME": &c.c.ConnFuncName,
		"PG_DECOY_PORTS":    &c.c.DecoyPorts,
	}
	for k, p := range envStr {
		if use(k) {
			*p = os.Getenv(k)
		}
	}
	envInt := map[string]*int{
		"PG_IKUAI_PORT":            &c.c.IKuaiPort,
		"PG_IKUAI_TIMEOUT":         &c.c.IKuaiTimeout,
		"PG_BAN_MINUTES":           &c.c.BanDurationMinutes,
		"PG_SYSLOG_PORT":           &c.c.SyslogPort,
		"PG_CONN_POLL_INTERVAL":    &c.c.ConnPollInterval,
		"PG_PORT_REFRESH_INTERVAL": &c.c.PortRefreshInt,
		"PG_WINDOW_SECONDS":        &c.c.WindowSeconds,
		"PG_SYN_FLOOD_THRESHOLD":   &c.c.SynFloodThreshold,
		"PG_PORT_SCAN_THRESHOLD":   &c.c.PortScanThreshold,
		"PG_CONN_RATE_THRESHOLD":   &c.c.ConnRateThreshold,
		"PG_UDP_FLOOD_THRESHOLD":   &c.c.UDPFloodThreshold,
		"PG_ALERT_COOLDOWN":        &c.c.AlertCooldown,
		"PG_EVENT_RETENTION_DAYS":  &c.c.EventRetentionDays,
		"PG_WEB_SESSION_HOURS":     &c.c.WebSessionHours,
		"PG_LOGIN_FAIL_THRESHOLD":  &c.c.LoginFailThreshold,
		"PG_LOGIN_FAIL_WINDOW":     &c.c.LoginFailWindow,
		"PG_DECOY_THRESHOLD":       &c.c.DecoyThreshold,
		"PG_DECOY_WINDOW":          &c.c.DecoyWindow,
		"PG_DECOY_BAN_MINUTES":     &c.c.DecoyBanMinutes,
		"PG_PROXY_PORT_START":      &c.c.ProxyPortStart,
		"PG_PROXY_PORT_END":        &c.c.ProxyPortEnd,
	}
	for k, p := range envInt {
		if use(k) {
			if n, err := strconv.Atoi(os.Getenv(k)); err == nil {
				*p = n
			}
		}
	}
	envBool := map[string]*bool{
		"PG_IKUAI_SSL":            &c.c.IKuaiSSL,
		"PG_IGNORE_PRIVATE_IPS":   &c.c.IgnorePrivateIPs,
		"PG_DETECTION_ENABLED":    &c.c.DetectionEnabled,
		"PG_SNIFFER_ENABLED":      &c.c.SnifferEnabled,
		"PG_SYSLOG_ENABLED":       &c.c.SyslogEnabled,
		"PG_CONN_POLL_ENABLED":    &c.c.ConnPollEnabled,
		"PG_PORT_REFRESH_ENABLED": &c.c.PortRefresh,
		"PG_LOGIN_FAIL_ENABLED":   &c.c.LoginFailEnabled,
		"PG_DECOY_ENABLED":        &c.c.DecoyEnabled,
		"PG_DECOY_BAN_ENABLED":    &c.c.DecoyBanEnabled,
		"PG_PROXY_ENABLED":        &c.c.ProxyEnabled,
	}
	for k, p := range envBool {
		if use(k) {
			v := os.Getenv(k)
			*p = strings.EqualFold(v, "true") || v == "1" || strings.EqualFold(v, "yes")
		}
	}
}

func (c *Config) normalize() {
	d := defaults()
	if c.c.WindowSeconds < 1 {
		c.c.WindowSeconds = d.WindowSeconds
	}
	if c.c.SynFloodThreshold < 1 {
		c.c.SynFloodThreshold = d.SynFloodThreshold
	}
	if c.c.PortScanThreshold < 1 {
		c.c.PortScanThreshold = d.PortScanThreshold
	}
	if c.c.ConnRateThreshold < 1 {
		c.c.ConnRateThreshold = d.ConnRateThreshold
	}
	if c.c.UDPFloodThreshold < 1 {
		c.c.UDPFloodThreshold = d.UDPFloodThreshold
	}
	if c.c.BanDurationMinutes < 0 {
		c.c.BanDurationMinutes = d.BanDurationMinutes
	}
	if c.c.IKuaiPort < 1 || c.c.IKuaiPort > 65535 {
		c.c.IKuaiPort = 80
	}
	if c.c.IKuaiTimeout < 1 {
		c.c.IKuaiTimeout = 5
	}
	if c.c.SyslogPort < 1 || c.c.SyslogPort > 65535 {
		c.c.SyslogPort = 5140
	}
	if c.c.ConnPollInterval < 5 {
		c.c.ConnPollInterval = 30
	}
	if c.c.PortRefreshInt < 30 {
		c.c.PortRefreshInt = 300
	}
	if c.c.AlertCooldown < 10 {
		c.c.AlertCooldown = 300
	}
	if c.c.LoginFailThreshold < 1 {
		c.c.LoginFailThreshold = d.LoginFailThreshold
	}
	if c.c.LoginFailWindow < 30 {
		c.c.LoginFailWindow = d.LoginFailWindow
	}
	// 日志保留至少 1 天，防止误填 0/负数导致清理逻辑异常
	if c.c.EventRetentionDays < 1 {
		c.c.EventRetentionDays = d.EventRetentionDays
	}
	if c.c.DecoyThreshold < 1 {
		c.c.DecoyThreshold = d.DecoyThreshold
	}
	if c.c.DecoyWindow < 10 {
		c.c.DecoyWindow = d.DecoyWindow
	}
	if c.c.DecoyBanMinutes < 1 {
		c.c.DecoyBanMinutes = d.DecoyBanMinutes
	}
	// 代理端口池限制在 compose 已暴露的物理范围内，避免配置出容器监听不到的端口。
	if c.c.ProxyPortStart < ProxyPortPhysicalMin || c.c.ProxyPortStart > ProxyPortPhysicalMax {
		c.c.ProxyPortStart = d.ProxyPortStart
	}
	if c.c.ProxyPortEnd < c.c.ProxyPortStart || c.c.ProxyPortEnd > ProxyPortPhysicalMax {
		c.c.ProxyPortEnd = d.ProxyPortEnd
	}
	if c.c.ProxyPortEnd < c.c.ProxyPortStart {
		c.c.ProxyPortEnd = c.c.ProxyPortStart
	}
}

// Ephemeral 是一次性连接测试所需的参数。
type Ephemeral struct {
	IKuaiHost     string
	IKuaiPort     int
	IKuaiSSL      bool
	IKuaiUsername string
	IKuaiPassword string
	IKuaiTimeout  int
}

// NewEphemeral 构造一个不持久化的配置，供"测试连接"等临时场景使用。
// 返回值没有绑定存储，不能调用 Update/SetPassword。
func NewEphemeral(e Ephemeral) *Config {
	c := &Config{c: defaults()}
	c.c.IKuaiHost = e.IKuaiHost
	c.c.IKuaiPort = e.IKuaiPort
	c.c.IKuaiSSL = e.IKuaiSSL
	c.c.IKuaiUsername = e.IKuaiUsername
	c.c.IKuaiPassword = e.IKuaiPassword
	c.c.IKuaiTimeout = e.IKuaiTimeout
	c.normalize()
	return c
}

// Snapshot 返回配置快照（用于页面渲染与 API）。密码字段会被脱敏。
func (c *Config) Snapshot(maskSecrets bool) map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	raw, _ := json.Marshal(c.c)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	if maskSecrets {
		out["ikuai_password"] = ""
	}
	return out
}

// Getters —— 全部加锁读取。

func (c *Config) IKuaiBaseURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	scheme := "http"
	if c.c.IKuaiSSL {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(c.c.IKuaiHost, strconv.Itoa(c.c.IKuaiPort))
}

func (c *Config) IKuaiCreds() (string, string, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.IKuaiUsername, c.c.IKuaiPassword, c.c.IKuaiTimeout
}

func (c *Config) BanMode() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.c.BanMode }
func (c *Config) BanMinutes() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.c.BanDurationMinutes }
func (c *Config) DetectionEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.DetectionEnabled
}
func (c *Config) SnifferEnabled() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.c.SnifferEnabled }
func (c *Config) SnifferIface() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.c.SnifferIface }
func (c *Config) SyslogEnabled() bool  { c.mu.RLock(); defer c.mu.RUnlock(); return c.c.SyslogEnabled }
func (c *Config) SyslogPort() int      { c.mu.RLock(); defer c.mu.RUnlock(); return c.c.SyslogPort }
func (c *Config) ConnPollEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.ConnPollEnabled
}
func (c *Config) ConnPollInterval() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.ConnPollInterval
}
func (c *Config) ConnFuncName() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.c.ConnFuncName }
func (c *Config) PortRefreshEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.PortRefresh
}
func (c *Config) PortRefreshInterval() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.PortRefreshInt
}
func (c *Config) EventRetentionDays() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.EventRetentionDays
}

// DecoyPorts 解析逗号分隔的诱饵端口列表，忽略非法值并去重。
func (c *Config) DecoyPorts() []int {
	c.mu.RLock()
	raw := c.c.DecoyPorts
	c.mu.RUnlock()
	seen := map[int]bool{}
	out := make([]int, 0)
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		n, err := strconv.Atoi(item)
		if err != nil || n < 1 || n > 65535 || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func (c *Config) DecoyEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.DecoyEnabled
}
func (c *Config) DecoyThreshold() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.DecoyThreshold
}
func (c *Config) DecoyWindow() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.DecoyWindow
}
func (c *Config) DecoyBanEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.DecoyBanEnabled
}
func (c *Config) DecoyBanMinutes() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.DecoyBanMinutes
}

func (c *Config) ProxyEnabled() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.c.ProxyEnabled }

// ProxyPortRange 返回当前配置的代理监听端口池范围 [start, end]。
func (c *Config) ProxyPortRange() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.ProxyPortStart, c.c.ProxyPortEnd
}

func (c *Config) WebUsername() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.c.WebUsername }
func (c *Config) WebPasswordHash() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.WebPasswordHash
}
func (c *Config) WebSessionHours() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.WebSessionHours
}

// Threshold 返回一次检测所需的全部阈值。
type Thresholds struct {
	Window, SynFlood, PortScan, ConnRate, UDPFlood, Cooldown int
	LoginFail, LoginFailWindow                               int
	LoginFailEnabled                                         bool
	DecoyEnabled, DecoyBanEnabled                            bool
	DecoyThreshold, DecoyWindow, DecoyBanMinutes             int
}

func (c *Config) Thresholds() Thresholds {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Thresholds{
		Window: c.c.WindowSeconds, SynFlood: c.c.SynFloodThreshold,
		PortScan: c.c.PortScanThreshold, ConnRate: c.c.ConnRateThreshold,
		UDPFlood: c.c.UDPFloodThreshold, Cooldown: c.c.AlertCooldown,
		LoginFail: c.c.LoginFailThreshold, LoginFailWindow: c.c.LoginFailWindow,
		LoginFailEnabled: c.c.LoginFailEnabled,
		DecoyEnabled:     c.c.DecoyEnabled, DecoyBanEnabled: c.c.DecoyBanEnabled,
		DecoyThreshold: c.c.DecoyThreshold,
		DecoyWindow:    c.c.DecoyWindow, DecoyBanMinutes: c.c.DecoyBanMinutes,
	}
}

// ProtectedIPs 返回需要保护的 IP/CIDR 列表。
func (c *Config) ProtectedIPs() []net.IPNet {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []net.IPNet
	for _, item := range strings.Split(c.c.Whitelist, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(item); err == nil {
			out = append(out, *network)
		} else if ip := net.ParseIP(item); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			out = append(out, net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return out
}

func (c *Config) IgnorePrivate() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.IgnorePrivateIPs
}

// IsProtected 判断 IP 是否在保护名单内（白名单/私网/环回），防止误封。
func (c *Config) IsProtected(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	if c.IgnorePrivate() && ip.IsPrivate() {
		return true
	}
	for _, network := range c.ProtectedIPs() {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Update 从 map 更新配置并持久化。未知键被忽略。
func (c *Config) Update(values map[string]any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	raw, _ := json.Marshal(c.c)
	var asMap map[string]any
	_ = json.Unmarshal(raw, &asMap)
	updates := make(map[string]any, len(values))
	for key, value := range values {
		if _, ok := asMap[key]; !ok {
			continue
		}
		// 用 JSON 往返做类型转换，避免 map[string]string 到强类型的手动映射
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		apply(&c.c, key, encoded)
		updates[key] = value
	}
	c.normalize()
	return c.s.SetConfigs(updates)
}

// SetPassword 更新 Web 管理密码（调用方负责生成哈希）。
func (c *Config) SetPassword(hash string) error {
	c.mu.Lock()
	c.c.WebPasswordHash = hash
	c.mu.Unlock()
	return c.s.SetConfigs(map[string]any{"web_password_hash": hash})
}

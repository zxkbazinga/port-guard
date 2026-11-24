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
	}
}

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
	c.applyEnv()
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
	}
}

func get(raw json.RawMessage, out any) {
	_ = json.Unmarshal(raw, out)
}

// applyEnv 用环境变量覆盖配置。
// 这是爱快原生应用（ipkg）的主要配置通道：option.json 的字段由爱快写入
// app/environment，start.sh 读取后 export 成 PG_* 变量传给本程序。
func (c *Config) applyEnv() {
	envStr := map[string]*string{
		"PG_IKUAI_HOST":     &c.c.IKuaiHost,
		"PG_IKUAI_USERNAME": &c.c.IKuaiUsername,
		"PG_IKUAI_PASSWORD": &c.c.IKuaiPassword,
		"PG_WEB_USERNAME":   &c.c.WebUsername,
		"PG_BAN_MODE":       &c.c.BanMode,
		"PG_WHITELIST":      &c.c.Whitelist,
		"PG_SNIFFER_IFACE":  &c.c.SnifferIface,
		"PG_CONN_FUNC_NAME": &c.c.ConnFuncName,
	}
	for k, p := range envStr {
		if v := os.Getenv(k); v != "" {
			*p = v
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
	}
	for k, p := range envInt {
		if v := os.Getenv(k); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
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
	}
	for k, p := range envBool {
		if v := os.Getenv(k); v != "" {
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

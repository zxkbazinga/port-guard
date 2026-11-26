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
	APIToken        string `json:"api_token"` // 供脚本调用的 Bearer Token，留空则禁用 Token 认证
	// 封禁
	BanDurationMinutes int    `json:"ban_duration_minutes"`
	Whitelist          string `json:"whitelist"`
	IgnorePrivateIPs   bool   `json:"ignore_private_ips"`
	// 检测
	DetectionEnabled bool `json:"detection_enabled"`
	SyslogPort       int  `json:"syslog_port"` // 接收 NAS / Windows / Ubuntu 安全日志的 UDP 端口
	// 阈值
	WindowSeconds      int `json:"window_seconds"`
	PortScanThreshold  int `json:"port_scan_threshold"`
	ConnRateThreshold  int `json:"conn_rate_threshold"`
	AlertCooldown      int `json:"alert_cooldown_seconds"`
	EventRetentionDays int `json:"event_retention_days"`
	// 登录爆破检测（来自 NAS / Windows / Ubuntu 转发的安全日志）
	LoginFailEnabled   bool `json:"login_fail_enabled"`
	LoginFailThreshold int  `json:"login_fail_threshold"`
	LoginFailWindow    int  `json:"login_fail_window_seconds"`
	// 串联代理：爱快把外网端口映射到本应用，由代理转发到内网服务
	ProxyEnabled   bool `json:"proxy_enabled"`
	ProxyPortStart int  `json:"proxy_port_start"`
	ProxyPortEnd   int  `json:"proxy_port_end"`
	// TLS 终结：证书与私钥文件（通过 SSH 放到 /data/certs/ 下即可）
	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`
	// TLS 证书自动同步：定时从内网网关拉取证书与私钥
	CertSyncEnabled         bool   `json:"cert_sync_enabled"`
	CertSyncURL             string `json:"cert_sync_url"`
	CertSyncCertURL         string `json:"cert_sync_cert_url"`
	CertSyncKeyURL          string `json:"cert_sync_key_url"`
	CertSyncToken           string `json:"cert_sync_token"`
	CertSyncIntervalSeconds int    `json:"cert_sync_interval_seconds"`
}

func defaults() values {
	return values{
		WebUsername: "admin", WebPasswordHash: "$2y$default$portguard", WebSessionHours: 12,
		BanDurationMinutes: 30,
		Whitelist:          "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16",
		IgnorePrivateIPs:   true,
		DetectionEnabled:   true, SyslogPort: 5140,
		WindowSeconds: 60, PortScanThreshold: 8,
		ConnRateThreshold: 60, AlertCooldown: 300,
		EventRetentionDays: 3,
		LoginFailEnabled:   true, LoginFailThreshold: 3, LoginFailWindow: 300,
		ProxyEnabled: false, ProxyPortStart: ProxyPortPhysicalMin, ProxyPortEnd: ProxyPortPhysicalMax,
		TLSCertFile: "/data/certs/fullchain.pem", TLSKeyFile: "/data/certs/privkey.pem",
		CertSyncEnabled: false, CertSyncURL: "", CertSyncCertURL: "", CertSyncKeyURL: "",
		CertSyncToken: "", CertSyncIntervalSeconds: 3600,
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
	case "api_token":
		get(raw, &v.APIToken)
	case "ban_duration_minutes":
		get(raw, &v.BanDurationMinutes)
	case "whitelist":
		get(raw, &v.Whitelist)
	case "ignore_private_ips":
		get(raw, &v.IgnorePrivateIPs)
	case "detection_enabled":
		get(raw, &v.DetectionEnabled)
	case "syslog_port":
		get(raw, &v.SyslogPort)
	case "window_seconds":
		get(raw, &v.WindowSeconds)
	case "port_scan_threshold":
		get(raw, &v.PortScanThreshold)
	case "conn_rate_threshold":
		get(raw, &v.ConnRateThreshold)
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
	case "proxy_enabled":
		get(raw, &v.ProxyEnabled)
	case "proxy_port_start":
		get(raw, &v.ProxyPortStart)
	case "proxy_port_end":
		get(raw, &v.ProxyPortEnd)
	case "tls_cert_file":
		get(raw, &v.TLSCertFile)
	case "tls_key_file":
		get(raw, &v.TLSKeyFile)
	case "cert_sync_enabled":
		get(raw, &v.CertSyncEnabled)
	case "cert_sync_url":
		get(raw, &v.CertSyncURL)
	case "cert_sync_cert_url":
		get(raw, &v.CertSyncCertURL)
	case "cert_sync_key_url":
		get(raw, &v.CertSyncKeyURL)
	case "cert_sync_token":
		get(raw, &v.CertSyncToken)
	case "cert_sync_interval_seconds":
		get(raw, &v.CertSyncIntervalSeconds)
	}
}

func get(raw json.RawMessage, out any) {
	_ = json.Unmarshal(raw, out)
}

// applyEnv 用环境变量补充配置（爱快 ipkg 的 option.json → environment → PG_* 通道）。
// 数据库中已显式保存过的键优先，环境变量只作为首次启动的初始值。
func (c *Config) applyEnv(stored map[string]json.RawMessage) {
	envKey := map[string]string{
		"PG_WEB_USERNAME":        "web_username",
		"PG_API_TOKEN":           "api_token",
		"PG_WHITELIST":           "whitelist",
		"PG_BAN_MINUTES":         "ban_duration_minutes",
		"PG_SYSLOG_PORT":         "syslog_port",
		"PG_CONN_FUNC_NAME":      "conn_func_name", // 兼容旧 ipkg 残留变量，忽略
		"PG_WINDOW_SECONDS":      "window_seconds",
		"PG_PORT_SCAN_THRESHOLD": "port_scan_threshold", "PG_CONN_RATE_THRESHOLD": "conn_rate_threshold",
		"PG_ALERT_COOLDOWN":       "alert_cooldown_seconds",
		"PG_EVENT_RETENTION_DAYS": "event_retention_days", "PG_WEB_SESSION_HOURS": "web_session_hours",
		"PG_LOGIN_FAIL_THRESHOLD": "login_fail_threshold", "PG_LOGIN_FAIL_WINDOW": "login_fail_window_seconds",
		"PG_PROXY_ENABLED":      "proxy_enabled",
		"PG_PROXY_PORT_START":   "proxy_port_start",
		"PG_PROXY_PORT_END":     "proxy_port_end",
		"PG_TLS_CERT_FILE":      "tls_cert_file",
		"PG_TLS_KEY_FILE":       "tls_key_file",
		"PG_CERT_SYNC_ENABLED":  "cert_sync_enabled",
		"PG_CERT_SYNC_URL":      "cert_sync_url",
		"PG_CERT_SYNC_CERT_URL": "cert_sync_cert_url",
		"PG_CERT_SYNC_KEY_URL":  "cert_sync_key_url",
		"PG_CERT_SYNC_TOKEN":    "cert_sync_token",
		"PG_CERT_SYNC_INTERVAL": "cert_sync_interval_seconds",
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
		return !saved
	}
	envStr := map[string]*string{
		"PG_WEB_USERNAME":       &c.c.WebUsername,
		"PG_API_TOKEN":          &c.c.APIToken,
		"PG_WHITELIST":          &c.c.Whitelist,
		"PG_TLS_CERT_FILE":      &c.c.TLSCertFile,
		"PG_TLS_KEY_FILE":       &c.c.TLSKeyFile,
		"PG_CERT_SYNC_URL":      &c.c.CertSyncURL,
		"PG_CERT_SYNC_CERT_URL": &c.c.CertSyncCertURL,
		"PG_CERT_SYNC_KEY_URL":  &c.c.CertSyncKeyURL,
		"PG_CERT_SYNC_TOKEN":    &c.c.CertSyncToken,
	}
	for k, p := range envStr {
		if use(k) {
			*p = os.Getenv(k)
		}
	}
	envInt := map[string]*int{
		"PG_BAN_MINUTES":          &c.c.BanDurationMinutes,
		"PG_SYSLOG_PORT":          &c.c.SyslogPort,
		"PG_WINDOW_SECONDS":       &c.c.WindowSeconds,
		"PG_PORT_SCAN_THRESHOLD":  &c.c.PortScanThreshold,
		"PG_CONN_RATE_THRESHOLD":  &c.c.ConnRateThreshold,
		"PG_ALERT_COOLDOWN":       &c.c.AlertCooldown,
		"PG_EVENT_RETENTION_DAYS": &c.c.EventRetentionDays,
		"PG_WEB_SESSION_HOURS":    &c.c.WebSessionHours,
		"PG_LOGIN_FAIL_THRESHOLD": &c.c.LoginFailThreshold,
		"PG_LOGIN_FAIL_WINDOW":    &c.c.LoginFailWindow,
		"PG_PROXY_PORT_START":     &c.c.ProxyPortStart,
		"PG_PROXY_PORT_END":       &c.c.ProxyPortEnd,
		"PG_CERT_SYNC_INTERVAL":   &c.c.CertSyncIntervalSeconds,
	}
	for k, p := range envInt {
		if use(k) {
			if n, err := strconv.Atoi(os.Getenv(k)); err == nil {
				*p = n
			}
		}
	}
	envBool := map[string]*bool{
		"PG_IGNORE_PRIVATE_IPS": &c.c.IgnorePrivateIPs,
		"PG_DETECTION_ENABLED":  &c.c.DetectionEnabled,
		"PG_LOGIN_FAIL_ENABLED": &c.c.LoginFailEnabled,
		"PG_PROXY_ENABLED":      &c.c.ProxyEnabled,
		"PG_CERT_SYNC_ENABLED":  &c.c.CertSyncEnabled,
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
	if c.c.PortScanThreshold < 1 {
		c.c.PortScanThreshold = d.PortScanThreshold
	}
	if c.c.ConnRateThreshold < 1 {
		c.c.ConnRateThreshold = d.ConnRateThreshold
	}
	if c.c.BanDurationMinutes < 0 {
		c.c.BanDurationMinutes = d.BanDurationMinutes
	}
	if c.c.SyslogPort < 1 || c.c.SyslogPort > 65535 {
		c.c.SyslogPort = d.SyslogPort
	}
	if c.c.AlertCooldown < 10 {
		c.c.AlertCooldown = d.AlertCooldown
	}
	if c.c.LoginFailThreshold < 1 {
		c.c.LoginFailThreshold = d.LoginFailThreshold
	}
	if c.c.LoginFailWindow < 30 {
		c.c.LoginFailWindow = d.LoginFailWindow
	}
	if c.c.EventRetentionDays < 1 {
		c.c.EventRetentionDays = d.EventRetentionDays
	}
	// 代理端口池限制在 compose 已暴露的物理范围内
	if c.c.ProxyPortStart < ProxyPortPhysicalMin || c.c.ProxyPortStart > ProxyPortPhysicalMax {
		c.c.ProxyPortStart = d.ProxyPortStart
	}
	if c.c.ProxyPortEnd < c.c.ProxyPortStart || c.c.ProxyPortEnd > ProxyPortPhysicalMax {
		c.c.ProxyPortEnd = d.ProxyPortEnd
	}
	if c.c.ProxyPortEnd < c.c.ProxyPortStart {
		c.c.ProxyPortEnd = c.c.ProxyPortStart
	}
	if strings.TrimSpace(c.c.TLSCertFile) == "" {
		c.c.TLSCertFile = d.TLSCertFile
	}
	if strings.TrimSpace(c.c.TLSKeyFile) == "" {
		c.c.TLSKeyFile = d.TLSKeyFile
	}
	c.c.CertSyncURL = strings.TrimSpace(c.c.CertSyncURL)
	c.c.CertSyncCertURL = strings.TrimSpace(c.c.CertSyncCertURL)
	c.c.CertSyncKeyURL = strings.TrimSpace(c.c.CertSyncKeyURL)
	if c.c.CertSyncIntervalSeconds < 60 || c.c.CertSyncIntervalSeconds > 86400 {
		c.c.CertSyncIntervalSeconds = d.CertSyncIntervalSeconds
	}
}

// Snapshot 返回配置快照（用于页面渲染与 API）。
func (c *Config) Snapshot(maskSecrets bool) map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	raw, _ := json.Marshal(c.c)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	if maskSecrets {
		if out["cert_sync_token"] != "" {
			out["cert_sync_token"] = "********"
		}
		if out["api_token"] != "" {
			out["api_token"] = "********"
		}
	}
	return out
}

// Getters —— 全部加锁读取。

func (c *Config) BanMinutes() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.c.BanDurationMinutes }
func (c *Config) DetectionEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.DetectionEnabled
}
func (c *Config) SyslogPort() int { c.mu.RLock(); defer c.mu.RUnlock(); return c.c.SyslogPort }
func (c *Config) EventRetentionDays() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.EventRetentionDays
}
func (c *Config) ProxyEnabled() bool { c.mu.RLock(); defer c.mu.RUnlock(); return c.c.ProxyEnabled }

func (c *Config) TLSFiles() (string, string) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.TLSCertFile, c.c.TLSKeyFile
}

// CertSyncSettings 返回证书自动同步配置。
func (c *Config) CertSyncSettings() (enabled bool, url, certURL, keyURL, token string, interval int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.CertSyncEnabled, c.c.CertSyncURL, c.c.CertSyncCertURL,
		c.c.CertSyncKeyURL, c.c.CertSyncToken, c.c.CertSyncIntervalSeconds
}

// ProxyPortRange 返回当前配置的代理监听端口池范围 [start, end]。
func (c *Config) ProxyPortRange() (int, int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.ProxyPortStart, c.c.ProxyPortEnd
}

func (c *Config) WebUsername() string { c.mu.RLock(); defer c.mu.RUnlock(); return c.c.WebUsername }
func (c *Config) APIToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.c.APIToken
}
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
	Window, PortScan, ConnRate, Cooldown int
	LoginFail, LoginFailWindow           int
	LoginFailEnabled                     bool
}

func (c *Config) Thresholds() Thresholds {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Thresholds{
		Window:   c.c.WindowSeconds,
		PortScan: c.c.PortScanThreshold, ConnRate: c.c.ConnRateThreshold,
		Cooldown:  c.c.AlertCooldown,
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
		// Web 页面显示的是掩码，原样提交时不能把真实 Token 覆盖成星号。
		if key == "cert_sync_token" || key == "api_token" {
			if s, ok := value.(string); ok && s == "********" {
				continue
			}
		}
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

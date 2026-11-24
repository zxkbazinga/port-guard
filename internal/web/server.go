// Package web 提供 Web 管理界面与 HTTP API。
package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zxkbazinga/port-guard/internal/ban"
	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/detector"
	"github.com/zxkbazinga/port-guard/internal/ikuai"
	"github.com/zxkbazinga/port-guard/internal/proxy"
	"github.com/zxkbazinga/port-guard/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Server 是 Web 服务。
type Server struct {
	cfg      *config.Config
	store    *store.Store
	client   *ikuai.Client
	engine   *detector.Engine
	sniffer  *detector.Sniffer
	syslog   *detector.SyslogReceiver
	decoy    *detector.DecoyListener
	probe    *detector.SourceProbe
	proxySrv *proxy.Server
	poller   *detector.Poller
	bans     *ban.Manager
	log      *slog.Logger
	sessions *sessionStore
	tmpl     *template.Template
	mux      *http.ServeMux
}

type Components struct {
	Cfg     *config.Config
	Store   *store.Store
	Client  *ikuai.Client
	Engine  *detector.Engine
	Sniffer *detector.Sniffer
	Syslog  *detector.SyslogReceiver
	Decoy   *detector.DecoyListener
	Probe   *detector.SourceProbe
	Proxy   *proxy.Server
	Poller  *detector.Poller
	Bans    *ban.Manager
	Log     *slog.Logger
}

func NewServer(c Components) (*Server, error) {
	funcs := template.FuncMap{
		"formatTime": func(ts int64) string {
			if ts == 0 {
				return "-"
			}
			return time.Unix(ts, 0).Format("2006-01-02 15:04:05")
		},
		"countdown": func(expiry int64) string {
			d := time.Until(time.Unix(expiry, 0))
			if d <= 0 {
				return "已到期"
			}
			return d.Round(time.Second).String()
		},
		// 返回 template.HTMLAttr：这些片段位于标签的属性位置，
		// 用普通 string 会被 html/template 当作不安全的属性名过滤成 ZgotmplZ，
		// 导致 checkbox / 下拉框的勾选状态无法回显。值均为硬编码常量，安全。
		"checked": func(v bool) template.HTMLAttr {
			if v {
				return "checked"
			}
			return ""
		},
		"selected": func(a, b string) template.HTMLAttr {
			if a == b {
				return "selected"
			}
			return ""
		},
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: c.Cfg, store: c.Store, client: c.Client, engine: c.Engine,
		sniffer: c.Sniffer, syslog: c.Syslog, decoy: c.Decoy, probe: c.Probe, proxySrv: c.Proxy,
		poller: c.Poller, bans: c.Bans,
		log: c.Log, sessions: newSessionStore(), tmpl: tmpl, mux: http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
	// 静态资源无需认证
	static, _ := fs.Sub(staticFS, "static")
	fileServer := http.FileServer(http.FS(static))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") {
			http.StripPrefix("/static/", fileServer).ServeHTTP(w, r)
			return
		}
		s.mux.ServeHTTP(w, r)
	})
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /login", s.loginPage)
	s.mux.HandleFunc("POST /login", s.loginSubmit)
	s.mux.HandleFunc("GET /logout", s.logout)
	s.mux.HandleFunc("GET /", s.withAuth(s.dashboard))
	s.mux.HandleFunc("GET /config", s.withAuth(s.configPage))
	s.mux.HandleFunc("POST /config", s.withAuth(s.configSave))
	s.mux.HandleFunc("GET /events", s.withAuth(s.eventsPage))
	s.mux.HandleFunc("GET /bans", s.withAuth(s.bansPage))
	s.mux.HandleFunc("GET /ports", s.withAuth(s.portsPage))
	s.mux.HandleFunc("GET /proxy", s.withAuth(s.proxyPage))
	// API
	s.mux.HandleFunc("GET /api/status", s.withAuth(s.apiStatus))
	s.mux.HandleFunc("GET /api/events", s.withAuth(s.apiEvents))
	s.mux.HandleFunc("GET /api/bans", s.withAuth(s.apiBans))
	s.mux.HandleFunc("GET /api/config", s.withAuth(s.apiConfigGet))
	s.mux.HandleFunc("POST /api/config", s.withAuth(s.apiConfigSet))
	s.mux.HandleFunc("POST /api/config/test-ikuai", s.withAuth(s.apiConfigTestIKuai))
	s.mux.HandleFunc("GET /api/ports", s.withAuth(s.apiPorts))
	s.mux.HandleFunc("POST /api/ports/sync", s.withAuth(s.apiPortSync))
	s.mux.HandleFunc("POST /api/ports", s.withAuth(s.apiPortAdd))
	s.mux.HandleFunc("DELETE /api/ports/{id}", s.withAuth(s.apiPortDelete))
	s.mux.HandleFunc("GET /api/forwards", s.withAuth(s.apiForwards))
	s.mux.HandleFunc("POST /api/forwards", s.withAuth(s.apiForwardAdd))
	s.mux.HandleFunc("POST /api/forwards/import", s.withAuth(s.apiForwardImport))
	s.mux.HandleFunc("POST /api/forwards/{id}/toggle", s.withAuth(s.apiForwardToggle))
	s.mux.HandleFunc("DELETE /api/forwards/{id}", s.withAuth(s.apiForwardDelete))
	s.mux.HandleFunc("POST /api/ban", s.withAuth(s.apiBan))
	s.mux.HandleFunc("POST /api/unban", s.withAuth(s.apiUnban))
	s.mux.HandleFunc("POST /api/probe", s.withAuth(s.apiProbe))
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
}

// ------------------------------------------------------------------ auth --

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("pg_session")
		if err != nil || !s.sessions.valid(cookie.Value) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "未登录"})
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}
		next(w, r)
	}
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, "login.html", map[string]any{"Error": ""})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username != s.cfg.WebUsername() || !verifyPassword(password, s.cfg.WebPasswordHash()) {
		s.render(w, "login.html", map[string]any{"Error": "用户名或密码错误"})
		return
	}
	token := s.sessions.create(time.Duration(s.cfg.WebSessionHours()) * time.Hour)
	http.SetCookie(w, &http.Cookie{Name: "pg_session", Value: token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(time.Duration(s.cfg.WebSessionHours()) * time.Hour)})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("pg_session"); err == nil {
		s.sessions.remove(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "pg_session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ----------------------------------------------------------------- pages --

func (s *Server) dashboard(w http.ResponseWriter, _ *http.Request) {
	bans, _ := s.store.ListBans(true)
	events, _ := s.store.ListEvents(8, 0, "")
	ports, _ := s.store.ListPorts(true)
	activeBans, _ := s.store.ActiveBanCount()
	attacks, _ := s.store.EventCount("attack", time.Now().Add(-24*time.Hour).Unix())
	s.render(w, "dashboard.html", map[string]any{
		"Title":  "概览",
		"Active": activeBans, "Attacks24h": attacks, "Ports": len(ports),
		"Bans": bans, "Events": events, "Mode": s.client.Mode(),
		"Sniffer": s.sniffer.Stats(), "Syslog": s.syslog.Stats(), "Decoy": s.decoyStats(),
		"Probe": s.probeStats(), "Proxy": s.proxyStats(),
		"Poller": s.poller.Stats(), "BanStats": s.bans.Stats(),
		"Enabled": s.cfg.DetectionEnabled(),
	})
}

func (s *Server) configPage(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "config.html", map[string]any{
		"Title": "系统配置",
		"Cfg":   s.cfg.Snapshot(true),
		"Mode":  s.client.Mode(),
		"Saved": false,
	})
}

func (s *Server) configSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	updates := map[string]any{}
	boolKeys := []string{"ikuai_ssl", "ignore_private_ips", "detection_enabled", "sniffer_enabled",
		"syslog_enabled", "conn_poll_enabled", "port_refresh_enabled", "login_fail_enabled",
		"decoy_enabled", "decoy_ban_enabled", "proxy_enabled"}
	for _, k := range boolKeys {
		updates[k] = r.FormValue(k) == "on" || r.FormValue(k) == "1"
	}
	intKeys := []string{"ikuai_port", "ikuai_timeout", "ban_duration_minutes", "syslog_port",
		"conn_poll_interval", "port_refresh_interval", "window_seconds", "syn_flood_threshold",
		"port_scan_threshold", "conn_rate_threshold", "udp_flood_threshold",
		"alert_cooldown_seconds", "event_retention_days", "web_session_hours",
		"login_fail_threshold", "login_fail_window_seconds",
		"decoy_threshold", "decoy_window_seconds", "decoy_ban_minutes",
		"proxy_port_start", "proxy_port_end"}
	for _, k := range intKeys {
		n, _ := strconv.Atoi(r.FormValue(k))
		updates[k] = n
	}
	strKeys := []string{"ikuai_host", "ikuai_username", "whitelist", "ban_mode",
		"sniffer_iface", "conn_func_name", "web_username", "decoy_ports"}
	for _, k := range strKeys {
		updates[k] = strings.TrimSpace(r.FormValue(k))
	}
	if pw := r.FormValue("ikuai_password"); pw != "" {
		updates["ikuai_password"] = pw
	}
	if pw := r.FormValue("web_password"); pw != "" {
		hash, err := HashPassword(pw)
		if err == nil {
			updates["web_password_hash"] = hash
		}
	}
	if err := s.cfg.Update(updates); err != nil {
		s.log.Error("保存配置失败", "err", err)
	}
	// 配置变更后重置引擎状态与 API 探测，并立即按新配置重登、同步端口映射
	s.engine.Reset()
	s.client.ResetProbe()
	s.client.ResetSession()
	s.reloadDecoy()
	s.reloadProxy()
	go s.poller.RefreshPorts()
	s.render(w, "config.html", map[string]any{
		"Title": "系统配置", "Cfg": s.cfg.Snapshot(true), "Mode": s.client.Mode(), "Saved": true,
	})
}

func (s *Server) eventsPage(w http.ResponseWriter, r *http.Request) {
	typ := r.URL.Query().Get("type")
	events, _ := s.store.ListEvents(200, 0, typ)
	s.render(w, "events.html", map[string]any{"Title": "事件日志", "Events": events, "Type": typ})
}

func (s *Server) bansPage(w http.ResponseWriter, _ *http.Request) {
	bans, _ := s.store.ListBans(false)
	s.render(w, "bans.html", map[string]any{"Title": "封禁管理", "Bans": bans})
}

func (s *Server) portsPage(w http.ResponseWriter, _ *http.Request) {
	ports, _ := s.store.ListPorts(false)
	s.render(w, "ports.html", map[string]any{"Title": "端口管理", "Ports": ports})
}

func (s *Server) proxyPage(w http.ResponseWriter, _ *http.Request) {
	forwards, _ := s.store.ListForwards(false)
	portStart, portEnd := s.cfg.ProxyPortRange()
	s.render(w, "proxy.html", map[string]any{
		"Title": "转发代理", "Forwards": forwards, "Proxy": s.proxyStats(),
		"PortStart": portStart, "PortEnd": portEnd,
	})
}

// ------------------------------------------------------------------- API --

func (s *Server) decoyStats() map[string]any {
	if s.decoy == nil {
		return map[string]any{"running": false, "ports": 0, "hits": 0}
	}
	return s.decoy.Stats()
}

func (s *Server) proxyStats() map[string]any {
	if s.proxySrv == nil {
		return map[string]any{"running": false, "enabled": false, "ports": []int{},
			"total": 0, "blocked": 0, "active": 0, "bytes": 0, "records": []any{}}
	}
	return s.proxySrv.Stats()
}

func (s *Server) reloadProxy() {
	if s.proxySrv != nil {
		_ = s.proxySrv.Reload()
	}
}

func (s *Server) probeStats() map[string]any {
	if s.probe == nil {
		return map[string]any{"running": false, "port": 0, "hits": 0, "records": []any{}}
	}
	return s.probe.Stats()
}

func (s *Server) reloadDecoy() {
	if s.decoy != nil {
		_ = s.decoy.Reload()
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) apiStatus(w http.ResponseWriter, _ *http.Request) {
	activeBans, _ := s.store.ActiveBanCount()
	attacks, _ := s.store.EventCount("attack", time.Now().Add(-24*time.Hour).Unix())
	ports, _ := s.store.ListPorts(true)
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": s.cfg.DetectionEnabled(), "ban_mode": s.client.Mode(),
		"active_bans": activeBans, "attacks_24h": attacks, "monitored_ports": len(ports),
		"sniffer": s.sniffer.Stats(), "syslog": s.syslog.Stats(), "probe": s.probeStats(),
		"decoy": s.decoyStats(), "proxy": s.proxyStats(),
		"poller": s.poller.Stats(), "engine": s.engine.Stats(), "ban": s.bans.Stats(),
	})
}

func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 1000 {
		limit = 100
	}
	events, err := s.store.ListEvents(limit, 0, r.URL.Query().Get("type"))
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, events)
}

func (s *Server) apiBans(w http.ResponseWriter, _ *http.Request) {
	bans, err := s.store.ListBans(false)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, bans)
}

func (s *Server) apiConfigGet(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, s.cfg.Snapshot(true))
}

func (s *Server) apiConfigSet(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if err := normalizeConfigPayload(payload); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if err := s.cfg.Update(payload); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.engine.Reset()
	s.client.ResetProbe()
	s.client.ResetSession()
	s.reloadDecoy()
	s.reloadProxy()
	go s.poller.RefreshPorts()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// normalizeConfigPayload 把 API 里的明文 web_password 转成哈希字段。
// 模块级保存和原来的全量保存共用 /api/config，密码字段不能原样入库。
// 留空表示不修改密码，此时不写入任何密码字段。
func normalizeConfigPayload(payload map[string]any) error {
	raw, ok := payload["web_password"]
	delete(payload, "web_password")
	if !ok {
		return nil
	}
	plain, ok := raw.(string)
	if !ok || plain == "" {
		return nil
	}
	hash, err := HashPassword(plain)
	if err != nil {
		return err
	}
	payload["web_password_hash"] = hash
	return nil
}

// apiConfigTestIKuai 使用请求中填写的参数测试爱快连接，不保存配置。
// 密码字段留空时沿用当前已保存的密码（页面不回显密码）。
func (s *Server) apiConfigTestIKuai(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Host     string `json:"ikuai_host"`
		Port     int    `json:"ikuai_port"`
		SSL      bool   `json:"ikuai_ssl"`
		Username string `json:"ikuai_username"`
		Password string `json:"ikuai_password"`
		Timeout  int    `json:"ikuai_timeout"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求格式错误: " + err.Error()})
		return
	}
	savedUser, savedPass, _ := s.cfg.IKuaiCreds()
	if strings.TrimSpace(p.Username) == "" {
		p.Username = savedUser
	}
	if p.Password == "" {
		p.Password = savedPass
	}
	result := ikuai.TestConnection(ikuai.TestParams{
		Host: strings.TrimSpace(p.Host), Port: p.Port, SSL: p.SSL,
		Username: strings.TrimSpace(p.Username), Password: p.Password, Timeout: p.Timeout,
	}, s.log)
	// 测试成功即把这套参数落库并立即同步端口映射，避免"测试能连、实际没配置"。
	// 密码为空表示沿用已保存的密码，不覆盖。
	if result.OK {
		updates := map[string]any{
			"ikuai_host": strings.TrimSpace(p.Host), "ikuai_port": p.Port,
			"ikuai_ssl": p.SSL, "ikuai_username": strings.TrimSpace(p.Username),
			"ikuai_timeout": p.Timeout,
		}
		if p.Password != "" {
			updates["ikuai_password"] = p.Password
		}
		if err := s.cfg.Update(updates); err != nil {
			s.log.Error("测试连接成功后保存配置失败", "err", err)
		} else {
			s.client.ResetSession()
			s.client.ResetProbe()
			if n, err := s.poller.RefreshPorts(); err == nil {
				result.SyncedPorts = n
			}
			result.Saved = true
		}
	}
	writeJSON(w, 200, result)
}

func (s *Server) apiPorts(w http.ResponseWriter, _ *http.Request) {
	ports, err := s.store.ListPorts(false)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, ports)
}

// apiPortSync 手动触发一次爱快端口映射同步，返回同步到的条数。
func (s *Server) apiPortSync(w http.ResponseWriter, _ *http.Request) {
	s.client.ResetSession()
	n, err := s.poller.RefreshPorts()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "同步失败: " + err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "synced": n})
}

func (s *Server) apiPortAdd(w http.ResponseWriter, r *http.Request) {
	var p struct {
		ExternalPort int    `json:"external_port"`
		InternalPort int    `json:"internal_port"`
		InternalIP   string `json:"internal_ip"`
		Protocol     string `json:"protocol"`
		Label        string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if p.ExternalPort < 1 || p.ExternalPort > 65535 {
		writeJSON(w, 400, map[string]any{"error": "外部端口无效"})
		return
	}
	if p.InternalPort == 0 {
		p.InternalPort = p.ExternalPort
	}
	if p.Protocol == "" {
		p.Protocol = "tcp"
	}
	err := s.store.UpsertPort(store.Port{
		ExternalPort: p.ExternalPort, InternalPort: p.InternalPort, InternalIP: p.InternalIP,
		Protocol: p.Protocol, Label: p.Label, Enabled: true, Source: "manual",
	})
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.portSync()
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiPortDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.store.DeletePort(id); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.portSync()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// ---------------------------------------------------------- forwards API --

func (s *Server) apiForwards(w http.ResponseWriter, _ *http.Request) {
	forwards, err := s.store.ListForwards(false)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, forwards)
}

func (s *Server) apiForwardAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ListenPort  int    `json:"listen_port"`
		BackendIP   string `json:"backend_ip"`
		BackendPort int    `json:"backend_port"`
		Protocol    string `json:"protocol"`
		Label       string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求格式错误"})
		return
	}
	if body.ListenPort < 1 || body.ListenPort > 65535 || body.BackendPort < 1 || body.BackendPort > 65535 {
		writeJSON(w, 400, map[string]any{"error": "端口必须在 1-65535 之间"})
		return
	}
	if net.ParseIP(body.BackendIP) == nil {
		writeJSON(w, 400, map[string]any{"error": "后端 IP 不合法"})
		return
	}
	if body.Protocol == "" {
		body.Protocol = "tcp"
	}
	if err := s.store.UpsertForward(store.Forward{
		ListenPort: body.ListenPort, BackendIP: body.BackendIP, BackendPort: body.BackendPort,
		Protocol: body.Protocol, Label: body.Label, Enabled: true,
	}); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.reloadProxy()
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiForwardToggle(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	forwards, _ := s.store.ListForwards(false)
	enabled := false
	for _, f := range forwards {
		if f.ID == id {
			enabled = !f.Enabled
			break
		}
	}
	if err := s.store.SetForwardEnabled(id, enabled); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.reloadProxy()
	writeJSON(w, 200, map[string]any{"ok": true, "enabled": enabled})
}

func (s *Server) apiForwardDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.store.DeleteForward(id); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.reloadProxy()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// forwardImportItem 是一条由爱快映射生成的转发规则及对应的改映射提示。
type forwardImportItem struct {
	ListenPort   int    `json:"listen_port"`   // 分配给代理的监听端口（来自端口池）
	BackendIP    string `json:"backend_ip"`    // 原映射的内网 IP
	BackendPort  int    `json:"backend_port"`  // 原映射的内网端口
	ExternalPort int    `json:"external_port"` // 爱快上的外网端口
	Protocol     string `json:"protocol"`
	Label        string `json:"label"`
}

// apiForwardImport 从已同步的爱快端口映射一键生成转发规则。
// 后端地址/端口/协议/备注直接复用映射数据；监听端口从预映射的端口池自动分配，
// 因为 bridge 网络下容器只能监听 compose 已暴露的端口。
// 只生成规则，不修改爱快映射——改映射有断网风险，需用户在爱快侧手动完成。
func (s *Server) apiForwardImport(w http.ResponseWriter, _ *http.Request) {
	ports, err := s.store.ListPorts(false)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	existing, _ := s.store.ListForwards(false)

	// 已占用的后端（backendIP:port）不重复导入；已占用的监听端口不再分配。
	seenBackend := make(map[string]bool, len(existing))
	usedListen := make(map[int]bool, len(existing))
	for _, f := range existing {
		seenBackend[fmt.Sprintf("%s:%d/%s", f.BackendIP, f.BackendPort, f.Protocol)] = true
		usedListen[f.ListenPort] = true
	}

	portStart, portEnd := s.cfg.ProxyPortRange()
	nextPort := portStart
	items := make([]forwardImportItem, 0)
	poolExhausted := false
	for _, p := range ports {
		if p.Source != "ikuai" || !p.Enabled || p.InternalIP == "" || net.ParseIP(p.InternalIP) == nil {
			continue
		}
		if p.InternalPort < 1 || p.InternalPort > 65535 {
			continue
		}
		proto := p.Protocol
		if proto != "tcp" && proto != "udp" {
			proto = "tcp"
		}
		key := fmt.Sprintf("%s:%d/%s", p.InternalIP, p.InternalPort, proto)
		if seenBackend[key] {
			continue
		}
		// 从端口池取下一个空闲端口。
		listen := 0
		for nextPort <= portEnd {
			candidate := nextPort
			nextPort++
			if !usedListen[candidate] {
				listen = candidate
				break
			}
		}
		if listen == 0 {
			poolExhausted = true
			break
		}
		if err := s.store.UpsertForward(store.Forward{
			ListenPort: listen, BackendIP: p.InternalIP, BackendPort: p.InternalPort,
			Protocol: proto, Label: p.Label, Enabled: true,
		}); err != nil {
			continue
		}
		usedListen[listen] = true
		seenBackend[key] = true
		items = append(items, forwardImportItem{
			ListenPort: listen, BackendIP: p.InternalIP, BackendPort: p.InternalPort,
			ExternalPort: p.ExternalPort, Protocol: proto, Label: p.Label,
		})
	}
	s.reloadProxy()
	writeJSON(w, 200, map[string]any{
		"ok": true, "imported": len(items), "items": items, "pool_exhausted": poolExhausted,
	})
}

func (s *Server) portSync() {
	ports, _ := s.store.ListPorts(true)
	values := make([]int, 0, len(ports)*2)
	for _, p := range ports {
		values = append(values, p.ExternalPort, p.InternalPort)
	}
	s.engine.SetPorts(values)
}

func (s *Server) apiBan(w http.ResponseWriter, r *http.Request) {
	var p struct {
		IP      string `json:"ip"`
		Minutes int    `json:"minutes"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if p.IP == "" {
		writeJSON(w, 400, map[string]any{"error": "ip 必填"})
		return
	}
	if p.Reason == "" {
		p.Reason = "手工封禁"
	}
	if err := s.bans.ManualBan(p.IP, p.Minutes, p.Reason); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiUnban(w http.ResponseWriter, r *http.Request) {
	var p struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if err := s.bans.Unban(p.IP); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if s.proxySrv != nil {
		s.proxySrv.Unblock(p.IP)
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiProbe(w http.ResponseWriter, _ *http.Request) {
	s.client.ResetProbe()
	// 触发一次探测：用空封禁（none 模式除外）
	mode := s.cfg.BanMode()
	if mode == "none" {
		writeJSON(w, 200, map[string]any{"mode": "none"})
		return
	}
	_, err := s.client.Ban("203.0.113.254", 1, "port-guard probe")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	_ = s.client.Unban("203.0.113.254", "")
	writeJSON(w, 200, map[string]any{"mode": s.client.Mode()})
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("渲染模板失败", "template", name, "err", err)
		fmt.Fprint(w, "页面渲染失败，请查看日志")
	}
}

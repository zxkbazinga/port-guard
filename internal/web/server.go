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
	engine   *detector.Engine
	syslog   *detector.SyslogReceiver
	proxySrv *proxy.Server
	bans     *ban.Manager
	log      *slog.Logger
	sessions *sessionStore
	tmpl     *template.Template
	mux      *http.ServeMux
}

type Components struct {
	Cfg    *config.Config
	Store  *store.Store
	Engine *detector.Engine
	Syslog *detector.SyslogReceiver
	Proxy  *proxy.Server
	Bans   *ban.Manager
	Log    *slog.Logger
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
		// 返回 template.HTMLAttr：位于标签属性位置的片段必须用该类型，
		// 否则 html/template 会过滤成 ZgotmplZ。值均为硬编码常量，安全。
		"checked": func(v bool) template.HTMLAttr {
			if v {
				return "checked"
			}
			return ""
		},
	}
	tmpl, err := template.New("").Funcs(funcs).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: c.Cfg, store: c.Store, engine: c.Engine, syslog: c.Syslog, proxySrv: c.Proxy,
		bans: c.Bans, log: c.Log, sessions: newSessionStore(), tmpl: tmpl, mux: http.NewServeMux(),
	}
	s.routes()
	return s, nil
}

func (s *Server) Handler() http.Handler {
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
	s.mux.HandleFunc("GET /proxy", s.withAuth(s.proxyPage))
	// API
	s.mux.HandleFunc("GET /api/status", s.withAuth(s.apiStatus))
	s.mux.HandleFunc("GET /api/events", s.withAuth(s.apiEvents))
	s.mux.HandleFunc("GET /api/bans", s.withAuth(s.apiBans))
	s.mux.HandleFunc("GET /api/config", s.withAuth(s.apiConfigGet))
	s.mux.HandleFunc("POST /api/config", s.withAuth(s.apiConfigSet))
	s.mux.HandleFunc("GET /api/forwards", s.withAuth(s.apiForwards))
	s.mux.HandleFunc("POST /api/forwards", s.withAuth(s.apiForwardAdd))
	s.mux.HandleFunc("POST /api/forwards/{id}/toggle", s.withAuth(s.apiForwardToggle))
	s.mux.HandleFunc("DELETE /api/forwards/{id}", s.withAuth(s.apiForwardDelete))
	s.mux.HandleFunc("GET /api/forwards/logs", s.withAuth(s.apiForwardLogs))
	s.mux.HandleFunc("POST /api/forwards/logs/clear", s.withAuth(s.apiForwardLogsClear))
	s.mux.HandleFunc("POST /api/ban", s.withAuth(s.apiBan))
	s.mux.HandleFunc("POST /api/unban", s.withAuth(s.apiUnban))
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
	activeBans, _ := s.store.ActiveBanCount()
	attacks, _ := s.store.EventCount("attack", time.Now().Add(-24*time.Hour).Unix())
	s.render(w, "dashboard.html", map[string]any{
		"Title":  "概览",
		"Active": activeBans, "Attacks24h": attacks,
		"Bans": bans, "Events": events,
		"Syslog": s.syslog.Stats(), "Proxy": s.proxyStats(),
		"BanStats": s.bans.Stats(), "Engine": s.engine.Stats(),
		"Enabled": s.cfg.DetectionEnabled(),
	})
}

func (s *Server) configPage(w http.ResponseWriter, _ *http.Request) {
	s.render(w, "config.html", map[string]any{
		"Title": "系统配置", "Cfg": s.cfg.Snapshot(true), "Saved": false,
	})
}

func (s *Server) configSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	updates := map[string]any{}
	boolKeys := []string{"ignore_private_ips", "detection_enabled", "login_fail_enabled", "proxy_enabled"}
	for _, k := range boolKeys {
		updates[k] = r.FormValue(k) == "on" || r.FormValue(k) == "1"
	}
	intKeys := []string{"ban_duration_minutes", "syslog_port", "window_seconds", "syn_flood_threshold",
		"port_scan_threshold", "conn_rate_threshold", "udp_flood_threshold",
		"alert_cooldown_seconds", "event_retention_days", "web_session_hours",
		"login_fail_threshold", "login_fail_window_seconds",
		"proxy_port_start", "proxy_port_end"}
	for _, k := range intKeys {
		n, _ := strconv.Atoi(r.FormValue(k))
		updates[k] = n
	}
	strKeys := []string{"whitelist", "web_username"}
	for _, k := range strKeys {
		updates[k] = strings.TrimSpace(r.FormValue(k))
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
	s.engine.Reset()
	s.reloadProxy()
	s.render(w, "config.html", map[string]any{
		"Title": "系统配置", "Cfg": s.cfg.Snapshot(true), "Saved": true,
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

func (s *Server) proxyPage(w http.ResponseWriter, _ *http.Request) {
	forwards, _ := s.store.ListForwards(false)
	portStart, portEnd := s.cfg.ProxyPortRange()
	s.render(w, "proxy.html", map[string]any{
		"Title": "转发代理", "Forwards": forwards, "Proxy": s.proxyStats(),
		"Logs": s.proxyRecords(1000), "PortStart": portStart, "PortEnd": portEnd,
	})
}

// ------------------------------------------------------------------- API --

func (s *Server) proxyStats() map[string]any {
	if s.proxySrv == nil {
		return map[string]any{"running": false, "enabled": false, "ports": []int{},
			"total": 0, "blocked": 0, "active": 0, "bytes": 0, "records": []proxy.ConnRecord{}}
	}
	return s.proxySrv.Stats()
}

func (s *Server) proxyRecords(limit int) []proxy.ConnRecord {
	if s.proxySrv == nil {
		return []proxy.ConnRecord{}
	}
	return s.proxySrv.Records(limit)
}

func (s *Server) reloadProxy() {
	if s.proxySrv != nil {
		_ = s.proxySrv.Reload()
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
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":     s.cfg.DetectionEnabled(),
		"active_bans": activeBans, "attacks_24h": attacks,
		"syslog": s.syslog.Stats(), "proxy": s.proxyStats(),
		"engine": s.engine.Stats(), "ban": s.bans.Stats(),
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
	s.reloadProxy()
	writeJSON(w, 200, map[string]any{"ok": true})
}

// normalizeConfigPayload 把 API 里的明文 web_password 转成哈希字段。
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

func (s *Server) apiForwardLogs(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 1000 {
		limit = 1000
	}
	records := s.proxyRecords(limit)
	writeJSON(w, 200, map[string]any{
		"max": 1000, "count": len(records), "records": records,
	})
}

func (s *Server) apiForwardLogsClear(w http.ResponseWriter, _ *http.Request) {
	if s.proxySrv != nil {
		s.proxySrv.ClearRecords()
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// -------------------------------------------------------------- bans API --

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
	if s.proxySrv != nil {
		s.proxySrv.Block(p.IP, p.Minutes)
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

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("渲染模板失败", "template", name, "err", err)
		fmt.Fprint(w, "页面渲染失败，请查看日志")
	}
}

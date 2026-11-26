// Package web 提供 Web 管理界面与 HTTP API。
package web

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/zxkbazinga/port-guard/internal/ban"
	"github.com/zxkbazinga/port-guard/internal/certsync"
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
	certSync *certsync.Manager
	log      *slog.Logger
	sessions *sessionStore
	tmpl     *template.Template
	mux      *http.ServeMux
}

type Components struct {
	Cfg      *config.Config
	Store    *store.Store
	Engine   *detector.Engine
	Syslog   *detector.SyslogReceiver
	Proxy    *proxy.Server
	Bans     *ban.Manager
	CertSync *certsync.Manager
	Log      *slog.Logger
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
		bans: c.Bans, certSync: c.CertSync, log: c.Log, sessions: newSessionStore(), tmpl: tmpl, mux: http.NewServeMux(),
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
	s.mux.HandleFunc("GET /api/certs/status", s.withAuth(s.apiCertStatus))
	s.mux.HandleFunc("POST /api/certs", s.withAuth(s.apiCertUpload))
	s.mux.HandleFunc("POST /api/certs/push", s.withAuth(s.apiCertPush))
	s.mux.HandleFunc("POST /api/certs/pull", s.withAuth(s.apiCertPull))
	s.mux.HandleFunc("GET /api/forwards", s.withAuth(s.apiForwards))
	s.mux.HandleFunc("POST /api/forwards", s.withAuth(s.apiForwardAdd))
	s.mux.HandleFunc("POST /api/forwards/{id}", s.withAuth(s.apiForwardUpdate))
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
		if s.validAPIToken(r) {
			next(w, r)
			return
		}
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

// validAPIToken 校验脚本调用的 Bearer Token。仅对 API 路径生效，且必须显式配置。
func (s *Server) validAPIToken(r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		return false
	}
	token := s.cfg.APIToken()
	if token == "" {
		return false
	}
	supplied := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		supplied = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	if supplied == "" {
		supplied = r.Header.Get("X-API-Token")
	}
	if supplied == "" {
		supplied = strings.TrimSpace(r.URL.Query().Get("token"))
	}
	return supplied != "" && subtle.ConstantTimeCompare([]byte(supplied), []byte(token)) == 1
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
		"PushCommand": s.pushCommand(),
	})
}

// pushCommand 生成可直接粘贴到 Gately「复制后执行」的单行命令。
// 这里用真实 Token（页面本身需登录才能访问），避免掩码值被误当作 Token 使用。
func (s *Server) pushCommand() string {
	token := s.cfg.APIToken()
	if token == "" {
		token = "YOUR_API_TOKEN"
	}
	return fmt.Sprintf(`curl -fsS -X POST -H "Authorization: Bearer %s" -F "cert=@$certFile" -F "key=@$keyFile" http://PORT_GUARD_IP:5657/api/certs/push`, token)
}

func (s *Server) configSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	updates := map[string]any{}
	boolKeys := []string{"ignore_private_ips", "detection_enabled", "login_fail_enabled", "proxy_enabled", "cert_sync_enabled"}
	for _, k := range boolKeys {
		updates[k] = r.FormValue(k) == "on" || r.FormValue(k) == "1"
	}
	intKeys := []string{"ban_duration_minutes", "syslog_port", "window_seconds",
		"port_scan_threshold", "conn_rate_threshold", "short_conn_threshold",
		"alert_cooldown_seconds", "event_retention_days", "web_session_hours",
		"login_fail_threshold", "login_fail_window_seconds",
		"proxy_port_start", "proxy_port_end", "cert_sync_interval_seconds"}
	for _, k := range intKeys {
		n, _ := strconv.Atoi(r.FormValue(k))
		updates[k] = n
	}
	strKeys := []string{"whitelist", "geo_mode", "web_username", "api_token", "tls_cert_file", "tls_key_file",
		"cert_sync_url", "cert_sync_cert_url", "cert_sync_key_url", "cert_sync_token"}
	for _, k := range strKeys {
		updates[k] = strings.TrimSpace(r.FormValue(k))
	}
	if pw := r.FormValue("web_password"); pw != "" {
		hash, err := HashPassword(pw)
		if err == nil {
			updates["web_password_hash"] = hash
		}
	}
	oldSyslogPort := s.cfg.SyslogPort()
	if err := s.cfg.Update(updates); err != nil {
		s.log.Error("保存配置失败", "err", err)
	}
	syslogErr := s.reloadSyslogIfPortChanged(oldSyslogPort)
	s.engine.Reset()
	s.reloadProxy()
	if s.certSync != nil {
		go func() { _ = s.certSync.SyncNow() }()
	}
	s.render(w, "config.html", map[string]any{
		"Title": "系统配置", "Cfg": s.cfg.Snapshot(true),
		"Saved": syslogErr == nil, "Error": errString(syslogErr),
		"PushCommand": s.pushCommand(),
	})
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
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

// reloadSyslogIfPortChanged 在 Syslog 端口被改动后重建 UDP 监听。
// 新端口绑定失败时把端口回滚到旧值，避免界面显示"已保存"但实际仍在监听旧端口。
func (s *Server) reloadSyslogIfPortChanged(oldPort int) error {
	if s.syslog == nil {
		return nil
	}
	newPort := s.cfg.SyslogPort()
	if newPort == oldPort {
		return nil
	}
	if err := s.syslog.Restart(); err != nil {
		_ = s.cfg.Update(map[string]any{"syslog_port": oldPort})
		return fmt.Errorf("Syslog 端口 %d 绑定失败，已回滚到 %d：%w", newPort, oldPort, err)
	}
	return nil
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
	oldSyslogPort := s.cfg.SyslogPort()
	if err := s.cfg.Update(payload); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	if err := s.reloadSyslogIfPortChanged(oldSyslogPort); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.engine.Reset()
	s.reloadProxy()
	if s.certSync != nil {
		go func() { _ = s.certSync.SyncNow() }()
	}
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

// -------------------------------------------------------------- certs API --

func (s *Server) apiCertStatus(w http.ResponseWriter, _ *http.Request) {
	certFile, keyFile := s.cfg.TLSFiles()
	status := map[string]any{
		"cert_path": certFile, "key_path": keyFile,
		"cert_exists": false, "key_exists": false, "ready": false,
	}
	certInfo, certErr := os.Stat(certFile)
	status["cert_exists"] = certErr == nil && !certInfo.IsDir()
	keyInfo, keyErr := os.Stat(keyFile)
	status["key_exists"] = keyErr == nil && !keyInfo.IsDir()
	if status["cert_exists"].(bool) && status["key_exists"].(bool) {
		certPEM, err1 := os.ReadFile(certFile)
		keyPEM, err2 := os.ReadFile(keyFile)
		if err1 == nil && err2 == nil {
			pair, err := tls.X509KeyPair(certPEM, keyPEM)
			if err == nil && len(pair.Certificate) > 0 {
				if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
					status["ready"] = true
					status["subject"] = leaf.Subject.String()
					status["not_after"] = leaf.NotAfter.Format("2006-01-02 15:04:05")
					status["dns_names"] = leaf.DNSNames
				}
			}
		}
	}
	if s.certSync != nil {
		status["sync"] = s.certSync.Stats()
	}
	writeJSON(w, 200, status)
}

func (s *Server) apiCertPull(w http.ResponseWriter, r *http.Request) {
	if s.certSync == nil {
		writeJSON(w, 400, map[string]any{"error": "证书自动同步不可用"})
		return
	}
	if err := s.certSync.SyncNow(); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.apiCertStatus(w, r)
}

func (s *Server) apiCertUpload(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求格式错误"})
		return
	}
	if err := s.saveCertPair(body.CertPEM, body.KeyPEM); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.apiCertStatus(w, r)
}

// apiCertPush 接收脚本（如 Gately 的「复制后执行」）以 multipart/form-data
// 推送的证书链与私钥。字段名兼容 cert/key、cert_pem/key_pem、fullchain/privkey。
func (s *Server) apiCertPush(w http.ResponseWriter, r *http.Request) {
	certPEM, keyPEM, err := readCertForm(r)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if err := s.saveCertPair(certPEM, keyPEM); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	s.log.Info("证书已通过推送接口更新并重载")
	s.apiCertStatus(w, r)
}

func readCertForm(r *http.Request) (string, string, error) {
	const maxUpload = 2 << 20 // 2 MiB，足够完整的证书链与私钥
	if err := r.ParseMultipartForm(maxUpload); err != nil {
		return "", "", fmt.Errorf("表单解析失败: %w", err)
	}
	readField := func(names ...string) string {
		for _, name := range names {
			if v := strings.TrimSpace(r.FormValue(name)); v != "" {
				return v
			}
		}
		return ""
	}
	readFile := func(names ...string) string {
		for _, name := range names {
			f, _, err := r.FormFile(name)
			if err != nil {
				continue
			}
			data, readErr := io.ReadAll(io.LimitReader(f, maxUpload))
			_ = f.Close()
			if readErr == nil {
				if v := strings.TrimSpace(string(data)); v != "" {
					return v
				}
			}
		}
		return ""
	}
	cert := readField("cert_pem", "cert", "fullchain")
	key := readField("key_pem", "key", "privkey")
	if cert == "" {
		cert = readFile("cert", "cert_pem", "fullchain", "cert_file")
	}
	if key == "" {
		key = readFile("key", "key_pem", "privkey", "key_file")
	}
	if cert == "" || key == "" {
		return "", "", fmt.Errorf("缺少证书或私钥（字段名 cert/key 或 cert_pem/key_pem）")
	}
	return cert, key, nil
}

// saveCertPair 校验证书与私钥匹配后原子写入配置路径并重建监听器。
func (s *Server) saveCertPair(certPEM, keyPEM string) error {
	certPEM, keyPEM = strings.TrimSpace(certPEM), strings.TrimSpace(keyPEM)
	if certPEM == "" || keyPEM == "" {
		return fmt.Errorf("证书链和私钥不能为空")
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil || len(pair.Certificate) == 0 {
		return fmt.Errorf("证书与私钥不匹配或格式错误：%s", errText(err))
	}
	certFile, keyFile := s.cfg.TLSFiles()
	if filepath.Clean(certFile) == filepath.Clean(keyFile) {
		return fmt.Errorf("证书与私钥路径不能相同")
	}
	if err := writePEMAtomic(certFile, []byte(certPEM+"\n"), 0o644); err != nil {
		return fmt.Errorf("写入证书失败：%s", err.Error())
	}
	if err := writePEMAtomic(keyFile, []byte(keyPEM+"\n"), 0o600); err != nil {
		return fmt.Errorf("写入私钥失败：%s", err.Error())
	}
	s.reloadProxy()
	return nil
}

func errText(err error) string {
	if err == nil {
		return "未知错误"
	}
	return err.Error()
}

// writePEMAtomic 在同目录临时文件写入后原子替换，避免写一半时代理重载读到损坏文件。
func writePEMAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".pg-cert-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
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

type forwardBody struct {
	ListenPort  int    `json:"listen_port"`
	BackendIP   string `json:"backend_ip"`
	BackendPort int    `json:"backend_port"`
	Protocol    string `json:"protocol"`
	Label       string `json:"label"`
	ListenTLS   bool   `json:"listen_tls"`
	BackendTLS  bool   `json:"backend_tls"`
}

// decodeForwardBody 解析并校验转发规则载荷。
func decodeForwardBody(r *http.Request) (forwardBody, error) {
	var body forwardBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		return body, fmt.Errorf("请求格式错误")
	}
	if body.ListenPort < 1 || body.ListenPort > 65535 || body.BackendPort < 1 || body.BackendPort > 65535 {
		return body, fmt.Errorf("端口必须在 1-65535 之间")
	}
	if net.ParseIP(body.BackendIP) == nil {
		return body, fmt.Errorf("后端 IP 不合法")
	}
	if body.Protocol == "" {
		body.Protocol = "tcp"
	}
	return body, nil
}

func (s *Server) apiForwardAdd(w http.ResponseWriter, r *http.Request) {
	body, err := decodeForwardBody(r)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if err := s.store.UpsertForward(store.Forward{
		ListenPort: body.ListenPort, BackendIP: body.BackendIP, BackendPort: body.BackendPort,
		Protocol: body.Protocol, Label: body.Label, Enabled: true,
		ListenTLS: body.ListenTLS, BackendTLS: body.BackendTLS,
	}); err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	s.reloadProxy()
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) apiForwardUpdate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	body, err := decodeForwardBody(r)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	// 保留原有的启用状态，编辑不改变启停。
	enabled := true
	forwards, _ := s.store.ListForwards(false)
	for _, f := range forwards {
		if f.ID == id {
			enabled = f.Enabled
			break
		}
	}
	if err := s.store.UpdateForward(id, store.Forward{
		ListenPort: body.ListenPort, BackendIP: body.BackendIP, BackendPort: body.BackendPort,
		Protocol: body.Protocol, Label: body.Label, Enabled: enabled,
		ListenTLS: body.ListenTLS, BackendTLS: body.BackendTLS,
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

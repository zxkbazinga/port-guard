package web

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/notify"
	"github.com/zxkbazinga/port-guard/internal/store"
	"github.com/zxkbazinga/port-guard/internal/update"
)

func TestTemplatesRender(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg, err := config.New(s)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Components{Cfg: cfg, Store: s, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := srv.tmpl.ExecuteTemplate(&buf, "config.html", map[string]any{
		"Cfg": cfg.Snapshot(true), "Saved": false, "PushCommand": srv.pushCommand(),
	}); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"ban_duration_minutes", "login_fail_enabled", "syslog_port",
		"proxy_enabled", "proxy_port_start", "proxy_port_end", "geo_mode",
		"仅中国大陆", "中国大陆 + 中国香港 + 中国澳门 + 中国台湾",
		"tls_cert_file", "tls_key_file",
		"certFileInput", "keyFileInput", "certUploadBtn", "certStatus",
		"api_token", "genTokenBtn", "copyPushBtn", "pushCommand", "api/certs/push",
		"dingtalk_enabled", "dingtalk_webhook", "dingtalk_secret", "dingtalk_keyword",
		"notifyTestBtn", "发送测试消息", "22349"} {
		if !strings.Contains(buf.String(), field) {
			t.Fatalf("配置页缺少字段 %s", field)
		}
	}
	for _, gone := range []string{"ikuai_host", "decoy_enabled", "conn_poll_enabled", "sniffer_enabled"} {
		if strings.Contains(buf.String(), gone) {
			t.Fatalf("配置页仍包含已删字段 %s", gone)
		}
	}

	buf.Reset()
	if err := srv.tmpl.ExecuteTemplate(&buf, "dashboard.html", map[string]any{
		"Title": "概览", "Enabled": true, "Attacks24h": 0, "Active": 0,
		"Syslog":   map[string]any{"running": false, "messages": 0},
		"Proxy":    map[string]any{"running": false, "ports": []int{}, "total": 0, "blocked": 0, "active": 0},
		"Engine":   map[string]any{"tracked_ips": 0},
		"BanStats": map[string]any{"banned_total": 0},
		"Events":   nil, "Bans": nil, "Version": "1.0.0",
	}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"转发代理", "Syslog", "最近事件", "检查更新", "checkUpdateBtn", "v1.0.0"} {
		if !strings.Contains(buf.String(), s) {
			t.Fatalf("概览页缺少 %q", s)
		}
	}
	for _, gone := range []string{"源 IP 验证", "诱饵端口", "爱快 API", "连接表诊断", "22222"} {
		if strings.Contains(buf.String(), gone) {
			t.Fatalf("概览页仍包含已删内容 %q", gone)
		}
	}

	buf.Reset()
	if err := srv.tmpl.ExecuteTemplate(&buf, "proxy.html", map[string]any{
		"Title": "转发代理", "Forwards": nil, "PortStart": 22300, "PortEnd": 22349,
		"Proxy": map[string]any{"running": false, "ports": []int{}, "total": 0,
			"blocked": 0, "active": 0, "records": nil},
		"Logs": nil,
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "转发规则") {
		t.Fatal("代理页缺少转发规则区块")
	}
	for _, want := range []string{"转发日志", "清空日志", "复制全部日志", "自动滚动", "fwdLogAutoScroll",
		"fwdKind", "fwdTlsOptions", "fwdBackendTLS", "HTTPS 网站", "editFwd", "fwdModalTitle"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("代理页缺少 %q", want)
		}
	}
	if strings.Contains(buf.String(), "fwdLogHeight") || strings.Contains(buf.String(), "fwdLogPause") {
		t.Fatal("代理页仍包含已删的框高输入或暂停刷新开关")
	}
	if strings.Contains(buf.String(), "从爱快映射导入") {
		t.Fatal("代理页仍包含已删的爱快导入按钮")
	}
}

func TestNormalizeConfigPayload(t *testing.T) {
	payload := map[string]any{"web_username": "bob", "web_password": "new-secret"}
	if err := normalizeConfigPayload(payload); err != nil {
		t.Fatalf("转换密码失败: %v", err)
	}
	if _, exists := payload["web_password"]; exists {
		t.Fatal("明文字段 web_password 未被移除")
	}
	hash, ok := payload["web_password_hash"].(string)
	if !ok || !verifyPassword("new-secret", hash) {
		t.Fatal("生成的密码哈希无法验证原密码")
	}
	if payload["web_username"] != "bob" {
		t.Fatal("无关字段被意外修改")
	}

	empty := map[string]any{"web_username": "alice", "web_password": ""}
	if err := normalizeConfigPayload(empty); err != nil {
		t.Fatalf("空密码处理失败: %v", err)
	}
	if _, exists := empty["web_password_hash"]; exists {
		t.Fatal("空密码不应覆盖已保存的哈希")
	}

	partial := map[string]any{"ban_duration_minutes": 30, "syslog_port": 5140}
	if err := normalizeConfigPayload(partial); err != nil {
		t.Fatalf("无密码载荷处理失败: %v", err)
	}
	if partial["ban_duration_minutes"] != 30 || partial["syslog_port"] != 5140 {
		t.Fatal("无密码载荷被意外修改")
	}
}

func TestCertUploadValidation(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "cert-upload.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg, err := config.New(s)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Components{Cfg: cfg, Store: s, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/certs",
		strings.NewReader(`{"cert_pem":"bad","key_pem":"bad"}`))
	rec := httptest.NewRecorder()
	srv.apiCertUpload(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("无效证书应返回 400，实际 %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "证书与私钥不匹配") {
		t.Fatalf("未返回证书校验错误：%s", rec.Body.String())
	}
}

func TestAPITokenAuth(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "token-auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.SetConfigs(map[string]any{"api_token": "s3cr3t-token"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.New(s)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Components{Cfg: cfg, Store: s, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	if srv.validAPIToken(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("非 API 路径不应允许 Token 认证")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	if srv.validAPIToken(req) {
		t.Fatal("缺少 Token 不应通过")
	}
	req.Header.Set("Authorization", "Bearer s3cr3t-token")
	if !srv.validAPIToken(req) {
		t.Fatal("正确 Bearer Token 应通过")
	}
	req2 := httptest.NewRequest(http.MethodGet, "/api/status", nil)
	req2.Header.Set("X-API-Token", "wrong")
	if srv.validAPIToken(req2) {
		t.Fatal("错误 Token 不应通过")
	}
	req3 := httptest.NewRequest(http.MethodGet, "/api/status?token=s3cr3t-token", nil)
	if !srv.validAPIToken(req3) {
		t.Fatal("query token 应通过")
	}
	if cmd := srv.pushCommand(); !strings.Contains(cmd, "s3cr3t-token") ||
		strings.Contains(cmd, "\n") {
		t.Fatalf("推送命令应单行且含真实 Token，实际 %q", cmd)
	}

	// 掩码后原样提交不覆盖真实 Token
	snap := cfg.Snapshot(true)
	if snap["api_token"] != "********" {
		t.Fatalf("Snapshot 应掩码 api_token，实际 %v", snap["api_token"])
	}
	if err := cfg.Update(map[string]any{"api_token": "********"}); err != nil {
		t.Fatal(err)
	}
	if cfg.APIToken() != "s3cr3t-token" {
		t.Fatal("掩码值不应覆盖真实 Token")
	}

	if err := cfg.Update(map[string]any{
		"dingtalk_webhook": "https://oapi.dingtalk.com/robot/send?access_token=abc",
		"dingtalk_secret":  "SEC-real",
	}); err != nil {
		t.Fatal(err)
	}
	snap = cfg.Snapshot(true)
	if snap["dingtalk_webhook"] != "********" || snap["dingtalk_secret"] != "********" {
		t.Fatalf("Snapshot 应掩码钉钉凭据，实际 %v / %v", snap["dingtalk_webhook"], snap["dingtalk_secret"])
	}
	if err := cfg.Update(map[string]any{"dingtalk_webhook": "********", "dingtalk_secret": "********"}); err != nil {
		t.Fatal(err)
	}
	if got := cfg.DingTalk(); got.Webhook != "https://oapi.dingtalk.com/robot/send?access_token=abc" ||
		got.Secret != "SEC-real" {
		t.Fatalf("掩码值不应覆盖真实钉钉凭据: %+v", got)
	}
}

func TestCertPushMultipart(t *testing.T) {
	certPEM, keyPEM := newTestCertPair(t)

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("cert_pem", certPEM)
	_ = w.WriteField("key_pem", keyPEM)
	_ = w.Close()
	req := httptest.NewRequest(http.MethodPost, "/api/certs/push", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	gotCert, gotKey, err := readCertForm(req)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(gotCert) != strings.TrimSpace(certPEM) ||
		strings.TrimSpace(gotKey) != strings.TrimSpace(keyPEM) {
		t.Fatal("multipart 字段解析结果不符")
	}

	// 文件字段形式（curl -F cert=@file）
	buf.Reset()
	w = multipart.NewWriter(&buf)
	cw, _ := w.CreateFormFile("cert", "fullchain.pem")
	_, _ = cw.Write([]byte(certPEM))
	kw, _ := w.CreateFormFile("key", "privkey.pem")
	_, _ = kw.Write([]byte(keyPEM))
	_ = w.Close()
	req = httptest.NewRequest(http.MethodPost, "/api/certs/push", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	gotCert, gotKey, err = readCertForm(req)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotCert, "BEGIN CERTIFICATE") || !strings.Contains(gotKey, "PRIVATE KEY") {
		t.Fatal("文件字段解析失败")
	}
}

func TestNotifyTestAPI(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "notify-test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg, err := config.New(s)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer hook.Close()
	if err := cfg.Update(map[string]any{"dingtalk_enabled": true, "dingtalk_webhook": hook.URL}); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := NewServer(Components{Cfg: cfg, Store: s, Notifier: notify.New(cfg, log), Log: log})
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	srv.apiNotifyTest(rec, httptest.NewRequest(http.MethodPost, "/api/notify/test", nil))
	if rec.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("测试发送应成功，code=%d calls=%d body=%s", rec.Code, calls.Load(), rec.Body.String())
	}

	if err := cfg.Update(map[string]any{"dingtalk_enabled": false}); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	srv.apiNotifyTest(rec, httptest.NewRequest(http.MethodPost, "/api/notify/test", nil))
	if rec.Code != http.StatusBadRequest || calls.Load() != 1 {
		t.Fatalf("关闭后不应发送，code=%d calls=%d", rec.Code, calls.Load())
	}
}

func newTestCertPair(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "push.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"push.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestApiUpdateCheck(t *testing.T) {
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v9.9.9","html_url":"https://example.com/r","published_at":"2026-02-02T00:00:00Z","body":"发布说明","draft":false,"prerelease":false}`))
	}))
	defer hook.Close()
	s, err := store.Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg, err := config.New(s)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Components{Cfg: cfg, Store: s, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	srv.updater = update.NewWithURL(hook.URL)

	rec := httptest.NewRecorder()
	srv.apiUpdateCheck(rec, httptest.NewRequest(http.MethodGet, "/api/update/check", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "9.9.9") {
		t.Fatalf("检查更新应返回最新版本，code=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "release_url") {
		t.Fatal("响应缺少 Release 链接")
	}
}

func TestApiUpdateCheckFailure(t *testing.T) {
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer hook.Close()
	s, err := store.Open(filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg, err := config.New(s)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Components{Cfg: cfg, Store: s, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	srv.updater = update.NewWithURL(hook.URL)

	rec := httptest.NewRecorder()
	srv.apiUpdateCheck(rec, httptest.NewRequest(http.MethodGet, "/api/update/check", nil))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "error") {
		t.Fatalf("上游失败应返回 502，code=%d body=%s", rec.Code, rec.Body.String())
	}
}

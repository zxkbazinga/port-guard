package web

import (
	"bytes"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/store"
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
		"Cfg": cfg.Snapshot(true), "Saved": false,
	}); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"ban_duration_minutes", "login_fail_enabled", "syslog_port",
		"proxy_enabled", "proxy_port_start", "proxy_port_end", "22349"} {
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
		"Events":   nil, "Bans": nil,
	}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"转发代理", "Syslog", "最近事件"} {
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
	for _, want := range []string{"转发日志", "清空日志", "复制全部日志", "fwdLogHeight"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("代理页缺少 %q", want)
		}
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

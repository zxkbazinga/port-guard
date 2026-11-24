package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/store"
)

func TestConfigTemplateRendersDecoyFields(t *testing.T) {
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
		"Cfg": cfg.Snapshot(true), "Mode": "auto", "Saved": false,
	}); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"decoy_enabled", "decoy_ports", "decoy_ban_enabled", "22200",
		"proxy_enabled", "proxy_port_start", "proxy_port_end", "22349"} {
		if !strings.Contains(buf.String(), field) {
			t.Fatalf("配置页缺少字段 %s", field)
		}
	}

	buf.Reset()
	if err := srv.tmpl.ExecuteTemplate(&buf, "dashboard.html", map[string]any{
		"Title": "概览", "Enabled": true, "Attacks24h": 0, "Active": 0, "Ports": 0, "Mode": "auto",
		"Sniffer": map[string]any{"running": false}, "Syslog": map[string]any{"running": false},
		"Decoy":  map[string]any{"running": false, "ports": 0, "hits": 0},
		"Probe":  map[string]any{"running": true, "port": 22222, "hits": 0, "records": nil},
		"Poller": map[string]any{"running": false, "conns_polled": 0, "ports_refreshed": 0},
		"Events": nil, "Bans": nil,
	}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"诱饵端口", "源 IP 验证", "22222", "转发代理"} {
		if !strings.Contains(buf.String(), s) {
			t.Fatalf("概览页缺少 %q", s)
		}
	}

	buf.Reset()
	if err := srv.tmpl.ExecuteTemplate(&buf, "proxy.html", map[string]any{
		"Title": "转发代理", "Forwards": nil,
		"Proxy": map[string]any{"running": false, "ports": []int{}, "total": 0,
			"blocked": 0, "active": 0, "records": nil},
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "转发规则") {
		t.Fatal("代理页缺少转发规则区块")
	}
}

func TestNormalizeConfigPayload(t *testing.T) {
	// 明文管理密码须转换为哈希，且不再以明文字段传给配置层。
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

	// 密码留空表示不修改：不写入任何密码字段。
	empty := map[string]any{"web_username": "alice", "web_password": ""}
	if err := normalizeConfigPayload(empty); err != nil {
		t.Fatalf("空密码处理失败: %v", err)
	}
	if _, exists := empty["web_password_hash"]; exists {
		t.Fatal("空密码不应覆盖已保存的哈希")
	}

	// 模块保存通常不包含密码字段，原样通过。
	partial := map[string]any{"ban_mode": "none", "syslog_port": 5140}
	if err := normalizeConfigPayload(partial); err != nil {
		t.Fatalf("无密码载荷处理失败: %v", err)
	}
	if partial["ban_mode"] != "none" || partial["syslog_port"] != 5140 {
		t.Fatal("无密码载荷被意外修改")
	}
}

func TestForwardImportFromIkuaiPorts(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "import.db"))
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

	// 两条爱快映射 + 一条手工端口（不应被导入）+ 一条禁用映射（不应被导入）。
	seed := []store.Port{
		{ExternalPort: 2222, InternalPort: 22, InternalIP: "192.168.1.10", Protocol: "tcp", Label: "NAS SSH", Enabled: true, Source: "ikuai"},
		{ExternalPort: 33890, InternalPort: 3389, InternalIP: "192.168.1.20", Protocol: "tcp", Label: "Windows RDP", Enabled: true, Source: "ikuai"},
		{ExternalPort: 9999, InternalPort: 9999, InternalIP: "192.168.1.30", Protocol: "tcp", Label: "手工", Enabled: true, Source: "manual"},
		{ExternalPort: 4444, InternalPort: 44, InternalIP: "192.168.1.40", Protocol: "tcp", Label: "禁用", Enabled: false, Source: "ikuai"},
	}
	for _, p := range seed {
		if err := s.UpsertPort(p); err != nil {
			t.Fatal(err)
		}
	}

	rec := httptest.NewRecorder()
	srv.apiForwardImport(rec, httptest.NewRequest("POST", "/api/forwards/import", nil))
	if rec.Code != 200 {
		t.Fatalf("状态码 %d, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		OK        bool                `json:"ok"`
		Imported  int                 `json:"imported"`
		Items     []forwardImportItem `json:"items"`
		Exhausted bool                `json:"pool_exhausted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Imported != 2 || len(resp.Items) != 2 {
		t.Fatalf("期望导入 2 条，实际 imported=%d items=%d", resp.Imported, len(resp.Items))
	}
	for _, it := range resp.Items {
		if it.ListenPort < config.ProxyPortPhysicalMin || it.ListenPort > config.ProxyPortPhysicalMax {
			t.Fatalf("监听端口 %d 不在端口池内", it.ListenPort)
		}
	}

	stored, _ := s.ListForwards(false)
	if len(stored) != 2 {
		t.Fatalf("期望库中 2 条转发规则，实际 %d", len(stored))
	}
	// 后端地址须复用映射数据。
	found := false
	for _, f := range stored {
		if f.BackendIP == "192.168.1.10" && f.BackendPort == 22 && f.Label == "NAS SSH" {
			found = true
		}
	}
	if !found {
		t.Fatal("未从映射带出后端地址/备注")
	}

	// 重复导入应幂等，不产生新规则。
	rec2 := httptest.NewRecorder()
	srv.apiForwardImport(rec2, httptest.NewRequest("POST", "/api/forwards/import", nil))
	var resp2 struct {
		Imported int `json:"imported"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &resp2)
	if resp2.Imported != 0 {
		t.Fatalf("重复导入应跳过全部，实际新增 %d", resp2.Imported)
	}
	stored2, _ := s.ListForwards(false)
	if len(stored2) != 2 {
		t.Fatalf("重复导入后规则数应仍为 2，实际 %d", len(stored2))
	}
}

func TestForwardImportHonorsConfiguredRange(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "range-import.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg, err := config.New(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(map[string]any{"proxy_port_start": 22310, "proxy_port_end": 22312}); err != nil {
		t.Fatal(err)
	}
	srv, err := NewServer(Components{Cfg: cfg, Store: s, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}

	// 4 条映射，但端口池只有 3 个 → 应导入 3 条并标记耗尽。
	for i := 0; i < 4; i++ {
		if err := s.UpsertPort(store.Port{
			ExternalPort: 3000 + i, InternalPort: 4000 + i,
			InternalIP: fmt.Sprintf("192.168.2.%d", i+1), Protocol: "tcp",
			Enabled: true, Source: "ikuai",
		}); err != nil {
			t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	srv.apiForwardImport(rec, httptest.NewRequest("POST", "/api/forwards/import", nil))
	var resp struct {
		Imported  int                 `json:"imported"`
		Items     []forwardImportItem `json:"items"`
		Exhausted bool                `json:"pool_exhausted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Imported != 3 || !resp.Exhausted {
		t.Fatalf("期望导入 3 条且池耗尽，实际 imported=%d exhausted=%v", resp.Imported, resp.Exhausted)
	}
	want := []int{22310, 22311, 22312}
	for i, it := range resp.Items {
		if it.ListenPort != want[i] {
			t.Fatalf("第 %d 条监听端口期望 %d，实际 %d", i, want[i], it.ListenPort)
		}
	}
}

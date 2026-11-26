package ban

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/detector"
	"github.com/zxkbazinga/port-guard/internal/notify"
	"github.com/zxkbazinga/port-guard/internal/store"
)

// TestNewBanNotifies 验证只有真正新增的封禁才推送钉钉，重复告警与保护名单不推送。
func TestNewBanNotifies(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "ban-notify.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg, err := config.New(s)
	if err != nil {
		t.Fatal(err)
	}

	received := make(chan string, 8)
	var calls atomic.Int32
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		calls.Add(1)
		select {
		case received <- string(raw):
		default:
		}
		_, _ = w.Write([]byte(`{"errcode":0,"errmsg":"ok"}`))
	}))
	defer hook.Close()
	if err := cfg.Update(map[string]any{"dingtalk_enabled": true, "dingtalk_webhook": hook.URL}); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	n := notify.New(cfg, log)
	n.Start()
	defer n.Stop()

	m := New(cfg, log, s)
	m.SetNotifier(n)
	alert := detector.Alert{IP: "66.228.62.150", Port: 22300, Proto: "tcp",
		Rule: "conn_rate", Reason: "连接频率异常", Detail: "60 秒内 80 次连接"}
	m.HandleAlert(alert)
	m.HandleAlert(alert)                                                             // 重复告警已在封禁中，不应重复通知
	m.HandleAlert(detector.Alert{IP: "10.0.0.9", Rule: "port_scan", Reason: "端口扫描"}) // 私网保护名单

	select {
	case body := <-received:
		if !strings.Contains(body, "66.228.62.150") || !strings.Contains(body, "conn_rate") {
			t.Fatalf("通知内容不符: %s", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未收到新封禁通知")
	}

	if err := m.ManualBan("8.8.8.8", 15, "手工测试"); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-received:
		if !strings.Contains(body, "8.8.8.8") || !strings.Contains(body, "手工测试") {
			t.Fatalf("手工封禁通知内容不符: %s", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未收到手工封禁通知")
	}

	if got := calls.Load(); got != 2 {
		t.Fatalf("应恰好发送 2 条通知（新封禁 + 手工封禁），实际 %d", got)
	}
}

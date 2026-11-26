package notify

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/store"
)

func newTestNotifier(t *testing.T, webhook string) (*Notifier, *config.Config) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "notify.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	cfg, err := config.New(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(map[string]any{"dingtalk_enabled": true, "dingtalk_webhook": webhook}); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return New(cfg, log), cfg
}

type captured struct {
	query string
	body  map[string]any
}

func captureServer(t *testing.T, response string, out chan<- captured) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("请求体不是合法 JSON: %v", err)
		}
		select {
		case out <- captured{query: r.URL.RawQuery, body: body}:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
}

func TestSendBanMarkdown(t *testing.T) {
	ch := make(chan captured, 1)
	srv := captureServer(t, `{"errcode":0,"errmsg":"ok"}`, ch)
	defer srv.Close()
	n, _ := newTestNotifier(t, srv.URL)
	n.SetCountryLookup(func(string) string { return "美国" })

	info := BanInfo{IP: "66.228.62.150", Reason: "连接频率异常", Rule: "conn_rate",
		Port: 22300, Proto: "tcp", Minutes: 30, Source: "attack"}
	if err := n.sendBan(context.Background(), info); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ch:
		if got.query != "" {
			t.Errorf("未配置密钥时不应带签名参数，got %q", got.query)
		}
		if got.body["msgtype"] != "markdown" {
			t.Errorf("msgtype = %v, want markdown", got.body["msgtype"])
		}
		md, ok := got.body["markdown"].(map[string]any)
		if !ok {
			t.Fatalf("markdown 字段缺失: %v", got.body)
		}
		text, _ := md["text"].(string)
		for _, want := range []string{"66.228.62.150", "美国", "连接频率异常", "conn_rate", "22300/tcp", "30 分钟", "自动防护"} {
			if !strings.Contains(text, want) {
				t.Errorf("消息缺少 %q: %s", want, text)
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("未收到钉钉请求")
	}
}

func TestSignedURLAndKeyword(t *testing.T) {
	ch := make(chan captured, 1)
	srv := captureServer(t, `{"errcode":0,"errmsg":"ok"}`, ch)
	defer srv.Close()
	n, cfg := newTestNotifier(t, srv.URL)
	if err := cfg.Update(map[string]any{
		"dingtalk_secret": "SEC-test-123", "dingtalk_keyword": "紧急警报",
	}); err != nil {
		t.Fatal(err)
	}

	if err := n.Test(); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-ch:
		q, err := url.ParseQuery(got.query)
		if err != nil {
			t.Fatal(err)
		}
		ts := q.Get("timestamp")
		if ts == "" {
			t.Fatal("缺少 timestamp 参数")
		}
		if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
			t.Fatalf("timestamp 不是毫秒时间戳: %q", ts)
		}
		mac := hmac.New(sha256.New, []byte("SEC-test-123"))
		_, _ = mac.Write([]byte(ts + "\nSEC-test-123"))
		want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if q.Get("sign") != want {
			t.Errorf("sign 与 HMAC 计算结果不一致\ngot  %s\nwant %s", q.Get("sign"), want)
		}
		md := got.body["markdown"].(map[string]any)
		text, _ := md["text"].(string)
		if !strings.Contains(text, "紧急警报") {
			t.Errorf("关键词未进入消息: %s", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("未收到钉钉请求")
	}
}

func TestDisabledSendsNothing(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
	}))
	defer srv.Close()
	n, cfg := newTestNotifier(t, srv.URL)
	if err := cfg.Update(map[string]any{"dingtalk_enabled": false}); err != nil {
		t.Fatal(err)
	}
	if err := n.sendBan(context.Background(), BanInfo{IP: "1.2.3.4"}); err != nil {
		t.Fatal(err)
	}
	if err := n.Test(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Errorf("关闭通知后仍发出了 %d 次请求", calls.Load())
	}
}

func TestDingTalkErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"errcode":310000,"errmsg":"keyword not found"}`))
	}))
	defer srv.Close()
	n, _ := newTestNotifier(t, srv.URL)
	if err := n.Test(); err == nil || !strings.Contains(err.Error(), "keyword not found") {
		t.Fatalf("期望返回钉钉错误，got %v", err)
	}

	bad, _ := newTestNotifier(t, "://bad-url")
	if err := bad.Test(); err == nil {
		t.Fatal("非法 Webhook 地址应报错")
	}
}

func TestBanAfterStopIsSafe(t *testing.T) {
	n, _ := newTestNotifier(t, "http://127.0.0.1:1")
	n.Start()
	n.Stop()
	n.Ban(BanInfo{IP: "1.2.3.4"}) // 退出后的残留告警不应 panic
	n.Stop()
}

func TestBanWorker(t *testing.T) {
	ch := make(chan captured, 1)
	srv := captureServer(t, `{"errcode":0,"errmsg":"ok"}`, ch)
	defer srv.Close()
	n, _ := newTestNotifier(t, srv.URL)
	n.Start()
	n.Ban(BanInfo{IP: "8.8.8.8", Reason: "端口扫描", Rule: "port_scan", Source: "attack"})
	select {
	case got := <-ch:
		md := got.body["markdown"].(map[string]any)
		if !strings.Contains(md["text"].(string), "8.8.8.8") {
			t.Error("异步通知未携带 IP")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("worker 未发送通知")
	}
	n.Stop()
}

package proxy

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/detector"
	"github.com/zxkbazinga/port-guard/internal/store"
)

func testSetup(t *testing.T) (*config.Config, *store.Store, *detector.Engine, *slog.Logger) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	cfg, err := config.New(s)
	if err != nil {
		t.Fatal(err)
	}
	_ = cfg.Update(map[string]any{"proxy_enabled": true, "detection_enabled": false})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := detector.New(cfg, log, nil)
	return cfg, s, eng, log
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func TestForwardEcho(t *testing.T) {
	cfg, s, eng, log := testSetup(t)
	backendPort := freePort(t)
	listenPort := freePort(t)

	// 后端回声服务
	bl, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", backendPort))
	if err != nil {
		t.Fatal(err)
	}
	defer bl.Close()
	go func() {
		for {
			c, err := bl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 128)
				n, _ := c.Read(buf)
				c.Write(buf[:n])
			}()
		}
	}()

	_ = s.UpsertForward(store.Forward{
		ListenPort: listenPort, BackendIP: "127.0.0.1", BackendPort: backendPort,
		Protocol: "tcp", Enabled: true,
	})
	p := New(cfg, log, eng, s)
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "hello-proxy")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello-proxy" {
		t.Fatalf("回声不符: %q", string(buf[:n]))
	}
	st := p.Stats()
	if st["total"].(uint64) != 1 {
		t.Fatalf("期望 total=1，实际 %v", st["total"])
	}
}

func TestLocalBanLifecycle(t *testing.T) {
	cfg, s, eng, log := testSetup(t)
	p := New(cfg, log, eng, s)

	if p.isLocallyBanned("8.8.8.8") {
		t.Fatal("初始不应封禁")
	}
	p.Block("8.8.8.8", 5)
	if !p.isLocallyBanned("8.8.8.8") {
		t.Fatal("Block 后应封禁")
	}
	if p.isLocallyBanned("1.1.1.1") {
		t.Fatal("其他 IP 不应被封禁")
	}
	p.Unblock("8.8.8.8")
	if p.isLocallyBanned("8.8.8.8") {
		t.Fatal("Unblock 后应解封")
	}

	// 过期封禁自动失效
	p.mu.Lock()
	p.localBan["9.9.9.9"] = time.Now().Add(-time.Minute).Unix()
	p.mu.Unlock()
	if p.isLocallyBanned("9.9.9.9") {
		t.Fatal("过期封禁不应生效")
	}

	// 0 分钟使用全局封禁时长（默认 30 分钟），不应永久封禁
	p.Block("5.5.5.5", 0)
	if !p.isLocallyBanned("5.5.5.5") {
		t.Fatal("0 分钟应使用全局封禁时长，应生效")
	}
	p.mu.Lock()
	until := p.localBan["5.5.5.5"]
	p.mu.Unlock()
	if until > time.Now().Add(31*time.Minute).Unix() {
		t.Fatalf("0 分钟不应超过全局时长，实际到期 %d", until)
	}
}

func TestDisabledForwardNotListened(t *testing.T) {
	cfg, s, eng, log := testSetup(t)
	port := freePort(t)
	_ = s.UpsertForward(store.Forward{
		ListenPort: port, BackendIP: "127.0.0.1", BackendPort: 12345,
		Protocol: "tcp", Enabled: false,
	})
	p := New(cfg, log, eng, s)
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	st := p.Stats()
	if len(st["ports"].([]int)) != 0 {
		t.Fatalf("停用的规则不应监听，实际 %v", st["ports"])
	}
}

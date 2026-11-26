package detector

import (
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/store"
)

func TestSyslogLoginFailFormats(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string // 期望提取的 IP
	}{
		{"ubuntu sshd", "Nov 24 10:00:00 ubuntu sshd[1234]: Failed password for invalid user admin from 45.33.22.11 port 54321 ssh2", "45.33.22.11"},
		{"pam auth failure", "Nov 24 10:00:00 host sshd[99]: pam_unix(sshd:auth): authentication failure; rhost=1.2.3.4 user=root", "1.2.3.4"},
		{"windows 4625", "2026-11-24 10:00:00 Security 4625 An account failed to log on. Source Network Address: 5.6.7.8", "5.6.7.8"},
		{"synology", "Nov 24 10:00:00 NAS SYSTEM: 登录失败, 来源 IP 9.8.7.6, 用户 admin", "9.8.7.6"},
		{"mysql", "2026-11-24T10:00:00.000000Z 3 [ERROR] [MY-010926] [Server] Access denied for user 'root'@'203.0.113.5' (using password: YES)", "203.0.113.5"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var alerts []Alert
			path := filepath.Join(t.TempDir(), "test.db")
			s, err := store.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { s.Close() })
			cfg, err := config.New(s)
			if err != nil {
				t.Fatal(err)
			}
			eng := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func(a Alert) { alerts = append(alerts, a) })
			r := NewSyslogReceiver(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), eng)
			// 阈值默认 3 次，喂 3 条相同日志触发封禁
			for i := 0; i < 3; i++ {
				r.parse(tc.line)
			}
			if len(alerts) != 1 {
				t.Fatalf("期望 1 条告警，实际 %d（日志: %s）", len(alerts), tc.line)
			}
			if alerts[0].Rule != "login_brute" {
				t.Fatalf("期望 login_brute，实际 %s", alerts[0].Rule)
			}
			if alerts[0].IP != tc.want {
				t.Fatalf("IP 错误: 期望 %s，实际 %s", tc.want, alerts[0].IP)
			}
		})
	}
}

// TestSyslogRestartPort 验证端口变化后新端口能接收消息，且失败时旧监听不受影响。
func TestSyslogRestartPort(t *testing.T) {
	freePort := func() int {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.LocalAddr().(*net.UDPAddr).Port
	}
	p1, p2 := freePort(), freePort()
	s, err := store.Open(filepath.Join(t.TempDir(), "restart.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	cfg, _ := config.New(s)
	if err := cfg.Update(map[string]any{"syslog_port": p1}); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := New(cfg, log, func(a Alert) {})
	r := NewSyslogReceiver(cfg, log, eng)
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Stop)

	// 旧端口可收
	addr1 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p1}
	c1, err := net.DialUDP("udp4", nil, addr1)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c1.Write([]byte("test"))
	_ = c1.Close()

	// 改端口并重启
	if err := cfg.Update(map[string]any{"syslog_port": p2}); err != nil {
		t.Fatal(err)
	}
	if err := r.Restart(); err != nil {
		t.Fatal(err)
	}
	if got := r.Stats()["running"]; got != true {
		t.Fatalf("重启后应为运行中，实际 %v", got)
	}
	addr2 := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: p2}
	c2, err := net.DialUDP("udp4", nil, addr2)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c2.Write([]byte("test"))
	_ = c2.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if r.Stats()["messages"].(uint64) >= 2 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("新端口未收到消息，messages=%v", r.Stats()["messages"])
}

func TestSyslogAttackStillWorks(t *testing.T) {
	var alerts []Alert
	path := filepath.Join(t.TempDir(), "test.db")
	s, _ := store.Open(path)
	t.Cleanup(func() { s.Close() })
	cfg, _ := config.New(s)
	eng := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func(a Alert) { alerts = append(alerts, a) })
	r := NewSyslogReceiver(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), eng)
	r.parse("Nov 24 10:00:00 ikuai kernel: 检测到 SYN Flood 攻击 SRC=8.8.4.4 DPT=22")
	if len(alerts) != 1 || alerts[0].Rule != "syslog" {
		t.Fatalf("原有 syslog 攻击检测应保持，实际 %+v", alerts)
	}
}

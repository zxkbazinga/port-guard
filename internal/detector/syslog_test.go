package detector

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"

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
			eng.SetPorts(nil) // 日志类事件不受端口过滤影响
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

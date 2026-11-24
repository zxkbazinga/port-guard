package detector

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/store"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
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
	_ = cfg.Update(map[string]any{
		"sniffer_enabled": false, "syslog_enabled": false,
		"conn_poll_enabled": false, "port_refresh_enabled": false,
		"window_seconds": 60, "syn_flood_threshold": 5,
		"port_scan_threshold": 4, "conn_rate_threshold": 10,
		"udp_flood_threshold": 10, "alert_cooldown_seconds": 300,
	})
	return cfg
}

func testEngine(t *testing.T, alerts *[]Alert) (*Engine, *config.Config) {
	t.Helper()
	cfg := testConfig(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := New(cfg, log, func(a Alert) { *alerts = append(*alerts, a) })
	eng.SetPorts([]int{22, 80, 443, 8080, 3306})
	return eng, cfg
}

func TestSynFlood(t *testing.T) {
	var alerts []Alert
	eng, _ := testEngine(t, &alerts)
	now := time.Now()
	for i := 0; i < 5; i++ {
		eng.Feed(Observation{Kind: KindSYN, IP: "8.8.8.8", Port: 22, TS: now.Add(time.Duration(i) * time.Second)})
	}
	if len(alerts) != 1 {
		t.Fatalf("期望 1 条告警，实际 %d", len(alerts))
	}
	if alerts[0].Rule != "syn_flood" {
		t.Fatalf("期望 syn_flood，实际 %s", alerts[0].Rule)
	}
	if alerts[0].IP != "8.8.8.8" {
		t.Fatalf("IP 错误: %s", alerts[0].IP)
	}
}

func TestPortScan(t *testing.T) {
	var alerts []Alert
	eng, _ := testEngine(t, &alerts)
	now := time.Now()
	for _, port := range []int{22, 80, 443, 8080} {
		eng.Feed(Observation{Kind: KindSYN, IP: "1.1.1.1", Port: port, TS: now})
	}
	if len(alerts) != 1 {
		t.Fatalf("期望 1 条告警，实际 %d", len(alerts))
	}
	if alerts[0].Rule != "port_scan" {
		t.Fatalf("期望 port_scan，实际 %s", alerts[0].Rule)
	}
}

func TestDecoyHitAlertOnlyByDefault(t *testing.T) {
	var alerts []Alert
	eng, cfg := testEngine(t, &alerts)
	_ = cfg.Update(map[string]any{"decoy_enabled": true})
	now := time.Now()
	eng.Feed(Observation{Kind: KindDecoy, IP: "8.8.4.4", Port: 22200, TS: now})
	if len(alerts) != 0 {
		t.Fatalf("只命中 1 个诱饵端口不应动作，实际 %d 条", len(alerts))
	}
	eng.Feed(Observation{Kind: KindDecoy, IP: "8.8.4.4", Port: 22201, TS: now.Add(time.Second)})
	if len(alerts) != 1 {
		t.Fatalf("命中 2 个不同诱饵端口应产生 1 条告警，实际 %d 条", len(alerts))
	}
	if alerts[0].Rule != "decoy_hit" || !alerts[0].NoBan {
		t.Fatalf("默认应只告警不封禁，实际 rule=%s noBan=%v", alerts[0].Rule, alerts[0].NoBan)
	}
}

func TestDecoyHitCanBan(t *testing.T) {
	var alerts []Alert
	eng, cfg := testEngine(t, &alerts)
	_ = cfg.Update(map[string]any{"decoy_enabled": true, "decoy_ban_enabled": true})
	now := time.Now()
	eng.Feed(Observation{Kind: KindDecoy, IP: "8.8.4.5", Port: 22200, TS: now})
	eng.Feed(Observation{Kind: KindDecoy, IP: "8.8.4.5", Port: 22202, TS: now.Add(time.Second)})
	if len(alerts) != 1 {
		t.Fatalf("期望 1 条告警，实际 %d 条", len(alerts))
	}
	if alerts[0].NoBan || alerts[0].Minutes != 1 {
		t.Fatalf("开启封禁后应 noBan=false 且时长 1 分钟，实际 %+v", alerts[0])
	}
}

func TestPrivateIPIgnored(t *testing.T) {
	var alerts []Alert
	eng, _ := testEngine(t, &alerts)
	now := time.Now()
	for i := 0; i < 20; i++ {
		eng.Feed(Observation{Kind: KindSYN, IP: "192.168.50.10", Port: 22, TS: now})
	}
	if len(alerts) != 0 {
		t.Fatalf("私网 IP 不应触发封禁，实际 %d 条", len(alerts))
	}
}

func TestWhitelistIPIgnored(t *testing.T) {
	var alerts []Alert
	eng, cfg := testEngine(t, &alerts)
	_ = cfg.Update(map[string]any{"whitelist": "203.0.113.0/24"})
	eng.Reset()
	now := time.Now()
	for i := 0; i < 20; i++ {
		eng.Feed(Observation{Kind: KindSYN, IP: "203.0.113.9", Port: 22, TS: now})
	}
	if len(alerts) != 0 {
		t.Fatalf("白名单 IP 不应触发封禁，实际 %d 条", len(alerts))
	}
}

func TestUnmonitoredPortIgnored(t *testing.T) {
	var alerts []Alert
	eng, _ := testEngine(t, &alerts)
	now := time.Now()
	for i := 0; i < 20; i++ {
		eng.Feed(Observation{Kind: KindSYN, IP: "9.9.9.9", Port: 9999, TS: now})
	}
	if len(alerts) != 0 {
		t.Fatalf("非映射端口不应触发封禁，实际 %d 条", len(alerts))
	}
}

func TestCooldown(t *testing.T) {
	var alerts []Alert
	eng, _ := testEngine(t, &alerts)
	now := time.Now()
	for i := 0; i < 5; i++ {
		eng.Feed(Observation{Kind: KindSYN, IP: "4.4.4.4", Port: 22, TS: now})
	}
	for i := 0; i < 5; i++ {
		eng.Feed(Observation{Kind: KindSYN, IP: "4.4.4.4", Port: 22, TS: now.Add(time.Second)})
	}
	if len(alerts) != 1 {
		t.Fatalf("冷却期内应只有 1 条告警，实际 %d", len(alerts))
	}
}

func TestLoginBruteForce(t *testing.T) {
	var alerts []Alert
	eng, _ := testEngine(t, &alerts)
	now := time.Now()
	// 默认阈值 3 次：前 2 次不应触发，第 3 次触发
	for i := 0; i < 2; i++ {
		eng.Feed(Observation{Kind: KindLoginFail, IP: "45.33.22.11", Port: 22, TS: now.Add(time.Duration(i) * time.Second)})
	}
	if len(alerts) != 0 {
		t.Fatalf("2 次失败不应封禁，实际 %d 条", len(alerts))
	}
	eng.Feed(Observation{Kind: KindLoginFail, IP: "45.33.22.11", Port: 22, TS: now.Add(2 * time.Second)})
	if len(alerts) != 1 {
		t.Fatalf("第 3 次失败应触发封禁，实际 %d 条", len(alerts))
	}
	if alerts[0].Rule != "login_brute" {
		t.Fatalf("期望 login_brute，实际 %s", alerts[0].Rule)
	}
}

func TestLoginFailDisabled(t *testing.T) {
	var alerts []Alert
	eng, cfg := testEngine(t, &alerts)
	_ = cfg.Update(map[string]any{"login_fail_enabled": false})
	eng.Reset()
	now := time.Now()
	for i := 0; i < 10; i++ {
		eng.Feed(Observation{Kind: KindLoginFail, IP: "45.33.22.12", Port: 22, TS: now})
	}
	if len(alerts) != 0 {
		t.Fatalf("关闭登录爆破检测后不应封禁，实际 %d 条", len(alerts))
	}
}

func TestLoginFailIgnoresPrivateIP(t *testing.T) {
	var alerts []Alert
	eng, _ := testEngine(t, &alerts)
	now := time.Now()
	for i := 0; i < 10; i++ {
		eng.Feed(Observation{Kind: KindLoginFail, IP: "192.168.1.50", Port: 22, TS: now})
	}
	if len(alerts) != 0 {
		t.Fatalf("私网 IP 的登录失败不应触发封禁，实际 %d 条", len(alerts))
	}
}

func TestSyslogAlert(t *testing.T) {
	var alerts []Alert
	eng, _ := testEngine(t, &alerts)
	eng.Feed(Observation{Kind: KindSyslog, IP: "5.6.7.8", Port: 22,
		Detail: "检测到端口扫描", TS: time.Now()})
	if len(alerts) != 1 {
		t.Fatalf("期望 1 条 syslog 告警，实际 %d", len(alerts))
	}
	if alerts[0].Rule != "syslog" {
		t.Fatalf("期望 syslog，实际 %s", alerts[0].Rule)
	}
}

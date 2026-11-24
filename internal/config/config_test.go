package config

import (
	"path/filepath"
	"testing"

	"github.com/zxkbazinga/port-guard/internal/store"
)

func newTestConfig(t *testing.T) *Config {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	cfg, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestEnvOverrides(t *testing.T) {
	// 注意：不能在 t.Setenv 之前调用 newTestConfig，因为 New() 会立即 applyEnv
	t.Setenv("PG_BAN_MINUTES", "45")
	t.Setenv("PG_BAN_MODE", "blacklist")
	t.Setenv("PG_IKUAI_HOST", "192.168.2.1")
	t.Setenv("PG_SNIFFER_ENABLED", "0")
	t.Setenv("PG_SYN_FLOOD_THRESHOLD", "99")

	cfg := newTestConfig(t)

	if got := cfg.BanMinutes(); got != 45 {
		t.Errorf("PG_BAN_MINUTES: got %d, want 45", got)
	}
	if got := cfg.BanMode(); got != "blacklist" {
		t.Errorf("PG_BAN_MODE: got %s, want blacklist", got)
	}
	if got := cfg.IKuaiBaseURL(); got != "http://192.168.2.1:80" {
		t.Errorf("PG_IKUAI_HOST: got %s", got)
	}
	if got := cfg.SnifferEnabled(); got {
		t.Error("PG_SNIFFER_ENABLED=0 应关闭抓包")
	}
	if got := cfg.Thresholds().SynFlood; got != 99 {
		t.Errorf("PG_SYN_FLOOD_THRESHOLD: got %d, want 99", got)
	}
}

// TestSavedConfigWinsOverEnv 验证 Web 保存的配置在容器重启后不会被
// ipkg environment 里的默认值（如 PG_IKUAI_HOST=127.0.0.1）覆盖。
func TestSavedConfigWinsOverEnv(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	// 模拟用户在 Web 配置页保存过的值
	first, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Update(map[string]any{
		"ikuai_host": "192.168.31.253", "ikuai_port": 443, "ikuai_ssl": true,
		"ikuai_username": "zzbazinga",
	}); err != nil {
		t.Fatal(err)
	}

	// 模拟容器重启：environment 仍带旧默认值
	t.Setenv("PG_IKUAI_HOST", "127.0.0.1")
	t.Setenv("PG_IKUAI_PORT", "80")
	t.Setenv("PG_IKUAI_SSL", "false")
	t.Setenv("PG_IKUAI_USERNAME", "admin")
	second, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	if got := second.IKuaiBaseURL(); got != "https://192.168.31.253:443" {
		t.Errorf("已保存的 host/port/ssl 应优先于环境变量，got %s", got)
	}
	user, _, _ := second.IKuaiCreds()
	if user != "zzbazinga" {
		t.Errorf("已保存的用户名应优先于环境变量，got %s", user)
	}
}

func TestIsProtected(t *testing.T) {
	cfg := newTestConfig(t)
	cases := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.100", true}, // 私网默认忽略
		{"10.0.0.1", true},
		{"127.0.0.1", true},
		{"8.8.8.8", false}, // 公网 IP 可被封禁
		{"1.1.1.1", false},
		{"not-an-ip", true}, // 非法 IP 视为保护
	}
	for _, c := range cases {
		if got := cfg.IsProtected(c.ip); got != c.want {
			t.Errorf("IsProtected(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestProxyPortRangeClamp(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "range.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// 超物理上限的结束端口应被夹回上限。
	c, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Update(map[string]any{"proxy_port_start": 22300, "proxy_port_end": 40000}); err != nil {
		t.Fatal(err)
	}
	start, end := c.ProxyPortRange()
	if start != ProxyPortPhysicalMin || end != ProxyPortPhysicalMax {
		t.Fatalf("期望端口池 [%d,%d]，实际 [%d,%d]", ProxyPortPhysicalMin, ProxyPortPhysicalMax, start, end)
	}

	// 在物理范围内的自定义区间应被保留。
	c2, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.Update(map[string]any{"proxy_port_start": 22310, "proxy_port_end": 22320}); err != nil {
		t.Fatal(err)
	}
	start, end = c2.ProxyPortRange()
	if start != 22310 || end != 22320 {
		t.Fatalf("期望自定义端口池 [22310,22320]，实际 [%d,%d]", start, end)
	}
}

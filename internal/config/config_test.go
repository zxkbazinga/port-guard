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
	t.Setenv("PG_CONN_RATE_THRESHOLD", "99")
	t.Setenv("PG_LOGIN_FAIL_ENABLED", "0")

	cfg := newTestConfig(t)

	if got := cfg.BanMinutes(); got != 45 {
		t.Errorf("PG_BAN_MINUTES: got %d, want 45", got)
	}
	if got := cfg.Thresholds().ConnRate; got != 99 {
		t.Errorf("PG_CONN_RATE_THRESHOLD: got %d, want 99", got)
	}
	if cfg.Thresholds().LoginFailEnabled {
		t.Error("PG_LOGIN_FAIL_ENABLED=0 应关闭登录爆破检测")
	}
}

// TestSavedConfigWinsOverEnv 验证 Web 保存的配置在容器重启后不会被
// ipkg environment 里的默认值覆盖。
func TestSavedConfigWinsOverEnv(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	first, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Update(map[string]any{"ban_duration_minutes": 60, "web_username": "guard"}); err != nil {
		t.Fatal(err)
	}

	// 模拟容器重启：environment 仍带旧默认值
	t.Setenv("PG_BAN_MINUTES", "30")
	t.Setenv("PG_WEB_USERNAME", "admin")
	second, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	if got := second.BanMinutes(); got != 60 {
		t.Errorf("已保存的封禁时长应优先于环境变量，got %d", got)
	}
	if got := second.WebUsername(); got != "guard" {
		t.Errorf("已保存的用户名应优先于环境变量，got %s", got)
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

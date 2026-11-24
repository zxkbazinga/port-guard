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

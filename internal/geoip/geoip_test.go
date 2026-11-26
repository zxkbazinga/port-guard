package geoip

import "testing"

func TestCheckerAllows(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip     string
		mode   string
		want   bool
		reason string
	}{
		{"1.0.1.1", ModeOff, true, "关闭限制时任何 IP 都放行"},
		{"8.8.8.8", ModeOff, true, "关闭限制时任何 IP 都放行"},
		{"1.0.1.1", ModeCN, true, "中国大陆地址"},
		{"223.5.5.5", ModeCN, true, "中国大陆 DNS"},
		{"8.8.8.8", ModeCN, false, "美国地址"},
		{"1.1.1.1", ModeCN, false, "境外 Anycast 地址"},
		{"102.220.160.148", ModeCN, false, "斯洛文尼亚扫描源"},
		{"122.185.44.206", ModeCN, false, "印度扫描源"},
		{"125.227.240.43", ModeCN, false, "中国台湾地址不属于仅大陆模式"},
		{"125.227.240.43", ModeCNAll, true, "含中国台湾的宽泛模式"},
		{"2400:3200::1", ModeCN, true, "中国大陆 IPv6"},
		{"2001:4860:4860::8888", ModeCN, false, "境外 IPv6"},
		{"192.168.1.10", ModeCN, true, "私网地址不受限制"},
		{"127.0.0.1", ModeCN, true, "环回地址不受限制"},
		{"not-an-ip", ModeCN, true, "无法解析的地址不误伤"},
	}
	for _, tc := range cases {
		if got := c.Allows(tc.ip, tc.mode); got != tc.want {
			t.Errorf("Allows(%q, %q) = %v, want %v (%s)", tc.ip, tc.mode, got, tc.want, tc.reason)
		}
	}
}

func TestNormalizeMode(t *testing.T) {
	cases := map[string]string{
		"cn":     ModeCN,
		" CN ":   ModeCN,
		"cn_all": ModeCNAll,
		"CN_ALL": ModeCNAll,
		"":       ModeOff,
		"off":    ModeOff,
		"bogus":  ModeOff,
	}
	for in, want := range cases {
		if got := NormalizeMode(in); got != want {
			t.Errorf("NormalizeMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func BenchmarkCheckerAllows(b *testing.B) {
	c, err := New()
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Allows("223.5.5.5", ModeCN)
	}
}

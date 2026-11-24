package store

import (
	"path/filepath"
	"testing"
)

// TestListPortsDecodesLegacyIkuaiLabel 验证旧数据里爱快来源的转义备注在展示时会被还原，
// 手工添加的备注则保持用户原样输入。
func TestListPortsDecodesLegacyIkuaiLabel(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for _, p := range []Port{
		{ExternalPort: 5000, InternalPort: 5000, Label: "DSM%20SSH", Source: "ikuai", Enabled: true},
		{ExternalPort: 5001, InternalPort: 5001, Label: "100%20done", Source: "manual", Enabled: true},
	} {
		if err := s.UpsertPort(p); err != nil {
			t.Fatal(err)
		}
	}
	ports, err := s.ListPorts(false)
	if err != nil {
		t.Fatal(err)
	}
	if len(ports) != 2 {
		t.Fatalf("期望 2 条端口，实际 %d", len(ports))
	}
	got := map[string]string{}
	for _, p := range ports {
		got[p.Source] = p.Label
	}
	if got["ikuai"] != "DSM SSH" {
		t.Errorf("爱快备注应解码，实际 %q", got["ikuai"])
	}
	if got["manual"] != "100%20done" {
		t.Errorf("手工备注应保持原样，实际 %q", got["manual"])
	}
}

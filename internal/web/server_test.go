package web

import "testing"

func TestNormalizeConfigPayload(t *testing.T) {
	// 明文管理密码须转换为哈希，且不再以明文字段传给配置层。
	payload := map[string]any{"web_username": "bob", "web_password": "new-secret"}
	if err := normalizeConfigPayload(payload); err != nil {
		t.Fatalf("转换密码失败: %v", err)
	}
	if _, exists := payload["web_password"]; exists {
		t.Fatal("明文字段 web_password 未被移除")
	}
	hash, ok := payload["web_password_hash"].(string)
	if !ok || !verifyPassword("new-secret", hash) {
		t.Fatal("生成的密码哈希无法验证原密码")
	}
	if payload["web_username"] != "bob" {
		t.Fatal("无关字段被意外修改")
	}

	// 密码留空表示不修改：不写入任何密码字段。
	empty := map[string]any{"web_username": "alice", "web_password": ""}
	if err := normalizeConfigPayload(empty); err != nil {
		t.Fatalf("空密码处理失败: %v", err)
	}
	if _, exists := empty["web_password_hash"]; exists {
		t.Fatal("空密码不应覆盖已保存的哈希")
	}

	// 模块保存通常不包含密码字段，原样通过。
	partial := map[string]any{"ban_mode": "none", "syslog_port": 5140}
	if err := normalizeConfigPayload(partial); err != nil {
		t.Fatalf("无密码载荷处理失败: %v", err)
	}
	if partial["ban_mode"] != "none" || partial["syslog_port"] != 5140 {
		t.Fatal("无密码载荷被意外修改")
	}
}

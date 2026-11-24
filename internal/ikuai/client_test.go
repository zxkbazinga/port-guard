package ikuai

import (
	"encoding/json"
	"testing"
)

func TestAPIOK(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{`{"code":0,"message":"success"}`, true},
		{`{"code":1,"message":"failed"}`, false},
		{`{"errcode":0}`, true},
		{`{"errcode":1001}`, false},
		{`{"Result":"session"}`, true},
		{`not json`, false},
	}
	for _, c := range cases {
		if got := apiOK(json.RawMessage(c.raw)); got != c.want {
			t.Errorf("apiOK(%s) = %v, want %v", c.raw, got, c.want)
		}
	}
}

func TestExtractRows(t *testing.T) {
	raw := `{"code":0,"data":[{"id":1,"external_port":8080,"internal_port":80,"internal_ip":"192.168.1.10","protocol":"tcp","enabled":"yes"}]}`
	rows := extractRows(json.RawMessage(raw), "data", "result")
	if len(rows) != 1 {
		t.Fatalf("期望 1 行，实际 %d", len(rows))
	}
	if num(rows[0]["external_port"]) != 8080 {
		t.Fatal("端口解析错误")
	}
}

func TestExtractRuleID(t *testing.T) {
	if got := extractRuleID(json.RawMessage(`{"code":0,"id":"42"}`)); got != "42" {
		t.Fatalf("期望 42，实际 %s", got)
	}
	if got := extractRuleID(json.RawMessage(`{"code":0}`)); got != "" {
		t.Fatalf("期望空，实际 %s", got)
	}
}

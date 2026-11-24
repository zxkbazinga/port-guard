package ikuai

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zxkbazinga/port-guard/internal/config"
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

// TestPortMappingsDecodesComment 验证爱快返回的 URL 转义备注（如 DSM%20SSH）在同步时还原。
func TestPortMappingsDecodesComment(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/Action/login":
			_, _ = w.Write([]byte(`{"Result":"sess-abc"}`))
		case "/Action/call":
			_, _ = io.ReadAll(r.Body)
			_, _ = w.Write([]byte(`{"code":0,"data":[` +
				`{"id":1,"external_port":5000,"internal_port":5000,"internal_ip":"192.168.1.10","comment":"DSM%20SSH","enabled":"yes"},` +
				`{"id":2,"external_port":5001,"internal_port":5001,"internal_ip":"192.168.1.11","tagname":"%E4%B8%AD%E6%96%87%E5%A4%87%E6%B3%A8","enabled":1}` +
				`]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	host, port := splitTestURL(t, srv.URL)

	cfg := config.NewEphemeral(config.Ephemeral{
		IKuaiHost: host, IKuaiPort: port, IKuaiUsername: "admin", IKuaiPassword: "pass", IKuaiTimeout: 2,
	})
	mappings, err := New(cfg, slog.Default()).PortMappings()
	if err != nil {
		t.Fatalf("拉取映射失败：%v", err)
	}
	if len(mappings) != 2 {
		t.Fatalf("期望 2 条映射，实际 %d", len(mappings))
	}
	if mappings[0].Comment != "DSM SSH" {
		t.Errorf("备注应解码为 DSM SSH，实际 %q", mappings[0].Comment)
	}
	if mappings[1].Comment != "中文备注" {
		t.Errorf("tagname 应解码为中文备注，实际 %q", mappings[1].Comment)
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

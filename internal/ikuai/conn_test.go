package ikuai

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zxkbazinga/port-guard/internal/config"
)

// TestConnectionsTryVariants 验证：首选形态返回 0 条时，会自动尝试下一种形态直到拿到数据。
func TestConnectionsTryVariants(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/Action/login":
			_, _ = w.Write([]byte(`{"Result":"sess-abc"}`))
		case "/Action/call":
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Func  string `json:"func_name"`
				Param struct {
					Type string `json:"TYPE"`
				} `json:"param"`
			}
			_ = json.Unmarshal(body, &req)
			calls = append(calls, req.Func+"|"+req.Param.Type)
			// 只有 conn + total,data 这种形态返回有效连接
			if req.Func == "conn" && req.Param.Type == "total,data" {
				_, _ = w.Write([]byte(`{"code":0,"data":[{"src_ip":"88.99.77.66","dst_ip":"192.168.31.50","dst_port":8080,"protocol":"tcp"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"code":0,"data":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	host, port := splitTestURL(t, srv.URL)

	cfg := config.NewEphemeral(config.Ephemeral{
		IKuaiHost: host, IKuaiPort: port, IKuaiUsername: "admin", IKuaiPassword: "pass", IKuaiTimeout: 2,
	})
	c := New(cfg, slog.Default())
	conns, err := c.Connections("monitor_conn")
	if err != nil {
		t.Fatalf("期望拉取成功，实际失败：%v", err)
	}
	if len(conns) != 1 || conns[0].SrcIP != "88.99.77.66" || conns[0].DstPort != 8080 {
		t.Fatalf("连接解析错误：%+v", conns)
	}
	if len(calls) < 2 {
		t.Fatalf("期望尝试多种形态，实际只调用 %d 次：%v", len(calls), calls)
	}
	diag := c.ConnDiagnostic()
	if !strings.Contains(diag.Variant, "conn") {
		t.Fatalf("诊断应记录成功的形态，实际：%+v", diag)
	}
	if diag.RowCount != 1 || !strings.Contains(diag.Sample, "88.99.77.66") {
		t.Fatalf("诊断样本错误：%+v", diag)
	}
	if diag.LastError != "" {
		t.Fatalf("成功后不应有错误：%s", diag.LastError)
	}
}

// TestConnectionsAllFail 验证：全部形态失败时返回错误并保留诊断，供状态页展示。
func TestConnectionsAllFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/Action/login":
			_, _ = w.Write([]byte(`{"Result":"sess-abc"}`))
		case "/Action/call":
			_, _ = w.Write([]byte(`{"code":1,"message":"method not found"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	host, port := splitTestURL(t, srv.URL)

	cfg := config.NewEphemeral(config.Ephemeral{
		IKuaiHost: host, IKuaiPort: port, IKuaiUsername: "admin", IKuaiPassword: "pass", IKuaiTimeout: 2,
	})
	c := New(cfg, slog.Default())
	_, err := c.Connections("")
	if err == nil {
		t.Fatal("期望全部形态失败时返回错误")
	}
	diag := c.ConnDiagnostic()
	if diag.LastError == "" {
		t.Fatal("期望诊断里保留最后一次错误")
	}
	if len(diag.Attempts) == 0 {
		t.Fatal("期望诊断里保留尝试记录")
	}
	if diag.Sample == "" {
		t.Fatal("期望诊断里保留响应样本")
	}
}

// TestConnVariantsPreferredFirst 验证用户配置的 func_name 排在最前。
func TestConnVariantsPreferredFirst(t *testing.T) {
	variants := connVariants("my_conn")
	if len(variants) == 0 {
		t.Fatal("候选形态不应为空")
	}
	if variants[0].Func != "my_conn" {
		t.Fatalf("首选形态应为 my_conn，实际 %s", variants[0].Func)
	}
	seen := map[string]bool{}
	for _, v := range variants {
		key := v.label()
		if seen[key] {
			t.Fatalf("存在重复形态：%s", key)
		}
		seen[key] = true
	}
}

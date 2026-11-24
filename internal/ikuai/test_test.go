package ikuai

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func splitTestURL(t *testing.T, raw string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(raw, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func TestConnectionSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/Action/login":
			_, _ = w.Write([]byte(`{"Result":"sess-abc"}`))
		case "/Action/call":
			_, _ = w.Write([]byte(`{"code":0,"data":[{"id":1,"external_port":8080,"internal_port":80,"internal_ip":"192.168.31.50","protocol":"tcp"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	host, port := splitTestURL(t, srv.URL)

	r := TestConnection(TestParams{Host: host, Port: port, Username: "admin", Password: "pass", Timeout: 2}, nil)
	if !r.OK {
		t.Fatalf("期望连接成功，实际失败：%+v", r.Steps)
	}
	if len(r.Steps) != 4 {
		t.Fatalf("期望 4 步诊断，实际 %d 步", len(r.Steps))
	}
	for _, step := range r.Steps {
		if !step.OK {
			t.Fatalf("步骤 %s 失败：%s", step.Name, step.Message)
		}
	}
	if r.Mappings != 1 {
		t.Fatalf("期望读到 1 条端口映射，实际 %d", r.Mappings)
	}
}

func TestConnectionNewFirmware(t *testing.T) {
	// 新固件登录响应：Result 是数字状态码，sess_key 由 Set-Cookie 返回
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/Action/login":
			http.SetCookie(w, &http.Cookie{Name: "username", Value: "admin"})
			http.SetCookie(w, &http.Cookie{Name: "sess_key", Value: "cookie-session-xyz"})
			_, _ = w.Write([]byte(`{"Result":10000,"code":0,"message":"成功"}`))
		case "/Action/call":
			// 验证调用 API 时带上了从 Cookie 提取的 sess_key
			ck, err := r.Cookie("sess_key")
			if err != nil || ck.Value != "cookie-session-xyz" {
				t.Errorf("调用 API 时 sess_key 不正确: %v", err)
			}
			_, _ = w.Write([]byte(`{"code":0,"data":[{"id":1,"external_port":8080,"internal_port":80}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	host, port := splitTestURL(t, srv.URL)

	r := TestConnection(TestParams{Host: host, Port: port, Username: "admin", Password: "pass", Timeout: 2}, nil)
	if !r.OK {
		t.Fatalf("新固件格式应连接成功，实际失败：%+v", r.Steps)
	}
	if r.Mappings != 1 {
		t.Fatalf("期望 1 条映射，实际 %d", r.Mappings)
	}
}

func TestConnectionLoginFailed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/Action/login" {
			_, _ = w.Write([]byte(`{"errcode":1,"message":"密码错误"}`))
			return
		}
		_, _ = w.Write([]byte(`{"code":0,"data":[]}`))
	}))
	defer srv.Close()
	host, port := splitTestURL(t, srv.URL)

	r := TestConnection(TestParams{Host: host, Port: port, Username: "admin", Password: "wrong", Timeout: 2}, nil)
	if r.OK {
		t.Fatal("期望登录失败，实际判定成功")
	}
	if len(r.Steps) != 3 || r.Steps[2].Name != "爱快登录" || r.Steps[2].OK {
		t.Fatalf("期望第 3 步登录失败，实际：%+v", r.Steps)
	}
	if !strings.Contains(r.Steps[2].Message, "密码错误") {
		t.Fatalf("错误信息应包含爱快返回内容，实际：%s", r.Steps[2].Message)
	}
}

func TestConnectionUnreachable(t *testing.T) {
	r := TestConnection(TestParams{Host: "127.0.0.1", Port: 1, Username: "admin", Password: "pass", Timeout: 1}, nil)
	if r.OK {
		t.Fatal("端口未监听时应判定失败")
	}
	if len(r.Steps) != 2 || r.Steps[1].Name != "TCP 连通" || r.Steps[1].OK {
		t.Fatalf("期望在第 2 步 TCP 连通失败，实际：%+v", r.Steps)
	}
}

func TestConnectionMissingHost(t *testing.T) {
	r := TestConnection(TestParams{Username: "admin", Password: "pass"}, nil)
	if r.OK || len(r.Steps) != 1 || r.Steps[0].Name != "参数检查" {
		t.Fatalf("空地址应第 1 步失败，实际：%+v", r.Steps)
	}
	if !strings.Contains(r.Steps[0].Message, "192.168.31.253") {
		t.Fatalf("应提示 bridge 模式填爱快 LAN IP，实际：%s", r.Steps[0].Message)
	}
}

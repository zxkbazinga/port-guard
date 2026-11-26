package update

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsBehind(t *testing.T) {
	cases := []struct {
		current string
		latest  string
		want    bool
	}{
		{"v1.0.0", "v1.0.0", false},
		{"1.0.0", "v1.0.1", true},
		{"v1.0.0", "v1.1.0", true},
		{"v1.0.0", "v2.0.0", true},
		{"v1.2.3", "v1.2.2", false},
		{"v1.10.0", "v1.9.0", false},
		{"dev", "v1.0.0", false}, // 开发版不误报更新
		{"", "v1.0.0", false},
		{"v1.0.0", "", false},
		{"custom-build", "v1.0.0", false},
		{"v1.2", "v1.2.1", true},
	}
	for _, c := range cases {
		if got := isBehind(c.current, c.latest); got != c.want {
			t.Errorf("isBehind(%q, %q) = %v, want %v", c.current, c.latest, got, c.want)
		}
	}
}

func TestCheckParsesRelease(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
			t.Errorf("Accept = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.0","html_url":"https://github.com/x/y/releases/tag/v1.2.0","published_at":"2026-01-01T00:00:00Z","body":"## 新功能\n- 检查更新","draft":false,"prerelease":false}`))
	}))
	defer srv.Close()

	c := &Checker{url: srv.URL}
	res, err := c.Check(context.Background(), "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if res.Latest != "1.2.0" || res.UpToDate {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.ReleaseURL == "" || res.PublishedAt == "" {
		t.Fatalf("missing release metadata: %+v", res)
	}
	if res.Notes == "" {
		t.Fatal("更新说明不应为空")
	}
}

func TestCheckUpToDate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v1.0.0","html_url":"u","draft":false,"prerelease":false}`))
	}))
	defer srv.Close()

	res, err := (&Checker{url: srv.URL}).Check(context.Background(), "v1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !res.UpToDate {
		t.Fatal("相同版本应显示已是最新")
	}
}

func TestCheckErrors(t *testing.T) {
	t.Run("prerelease", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"tag_name":"v2.0.0-beta","prerelease":true}`))
		}))
		defer srv.Close()
		if _, err := (&Checker{url: srv.URL}).Check(context.Background(), "v1.0.0"); err == nil {
			t.Fatal("预览版应报错")
		}
	})
	t.Run("http error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()
		if _, err := (&Checker{url: srv.URL}).Check(context.Background(), "v1.0.0"); err == nil {
			t.Fatal("HTTP 错误应报错")
		}
	})
}

// Package update 查询 GitHub 最新 Release，用于管理页的手动「检查更新」。
// 只在用户点击时请求一次，不参与启动与防护链路，失败不影响任何功能。
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	// releasesURL 返回最新正式版（排除 prerelease/draft）。
	releasesURL    = "https://api.github.com/repos/zxkbazinga/port-guard/releases/latest"
	requestTimeout = 8 * time.Second
	maxBody        = 1 << 20 // 1 MiB，防止异常响应占内存
)

// Result 是一次检查的结果。
type Result struct {
	Current     string `json:"current"`
	Latest      string `json:"latest"`
	UpToDate    bool   `json:"up_to_date"`
	ReleaseURL  string `json:"release_url"`
	PublishedAt string `json:"published_at"`
	Notes       string `json:"notes"`
}

// release 只解析需要的字段。
type release struct {
	TagName     string `json:"tag_name"`
	HTMLURL     string `json:"html_url"`
	PublishedAt string `json:"published_at"`
	Body        string `json:"body"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
}

// Checker 查询最新版本。Client 可注入以便测试。
type Checker struct {
	client *http.Client
	url    string
}

func New() *Checker {
	return &Checker{client: &http.Client{Timeout: requestTimeout}, url: releasesURL}
}

// NewWithURL 用自定义接口地址构造检查器，便于测试注入本地服务器。
func NewWithURL(url string) *Checker {
	return &Checker{client: &http.Client{Timeout: requestTimeout}, url: url}
}

// Check 查询最新版本并与当前版本比较。current 形如 v1.0.0 或 dev。
func (c *Checker) Check(ctx context.Context, current string) (*Result, error) {
	if c == nil {
		return nil, fmt.Errorf("检查器未初始化")
	}
	if c.client == nil {
		c.client = &http.Client{Timeout: requestTimeout}
	}
	endpoint := c.url
	if endpoint == "" {
		endpoint = releasesURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("请求构造失败: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "port-guard-update-check")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接 GitHub 失败: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GitHub 返回 HTTP %d", resp.StatusCode)
	}
	var rel release
	if err := json.Unmarshal(data, &rel); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}
	if rel.Draft || rel.Prerelease {
		return nil, fmt.Errorf("最新 Release 为预览版，暂不提示更新")
	}
	latest := normalizeVersion(rel.TagName)
	if latest == "" {
		return nil, fmt.Errorf("最新版本格式异常: %q", rel.TagName)
	}
	notes := strings.TrimSpace(rel.Body)
	if len(notes) > 2000 {
		notes = notes[:2000] + "\n…"
	}
	return &Result{
		Current:     strings.TrimSpace(current),
		Latest:      latest,
		UpToDate:    !isBehind(current, latest),
		ReleaseURL:  rel.HTMLURL,
		PublishedAt: rel.PublishedAt,
		Notes:       notes,
	}, nil
}

// normalizeVersion 去掉 v 前缀与多余的空白。
func normalizeVersion(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	return strings.TrimSpace(s)
}

// parseVersion 解析 x.y.z（可省略次要版本），失败返回 ok=false。
func parseVersion(s string) (major, minor, patch int, ok bool) {
	s = normalizeVersion(s)
	if s == "" || strings.ContainsAny(s, " \t") {
		return 0, 0, 0, false
	}
	parts := strings.Split(s, ".")
	if len(parts) > 3 || len(parts) == 0 {
		return 0, 0, 0, false
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return 0, 0, 0, false
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], true
}

// isBehind 判断 current 是否落后于 latest。dev 与无法解析的版本一律视为不落后，
// 避免开发版/自定义构建误报"有更新"。
func isBehind(current, latest string) bool {
	cm, cn, cp, ok1 := parseVersion(current)
	lm, ln, lp, ok2 := parseVersion(latest)
	if !ok1 || !ok2 {
		return false
	}
	if cm != lm {
		return cm < lm
	}
	if cn != ln {
		return cn < ln
	}
	return cp < lp
}

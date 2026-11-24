// Package ikuai 封装爱快路由器的 HTTP API。
//
// 爱快 Web 管理界面背后的 API：
//   - 登录：POST /Action/login，passwd=MD5(明文)，pass=base64("salt_113"+明文)
//   - 调用：POST /Action/call，Cookie: username=<user>; sess_key=<key>
//
// 注意：不同固件版本的字段名略有差异，因此封禁接口提供多种参数形态探测，
// 探测成功后缓存可用方案，避免每次调用都试错。
package ikuai

import (
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
)

// Mapping 是爱快端口映射（DNAT）规则。
type Mapping struct {
	ID           int    `json:"id"`
	ExternalPort int    `json:"external_port"`
	InternalPort int    `json:"internal_port"`
	InternalIP   string `json:"internal_ip"`
	Protocol     string `json:"protocol"`
	Comment      string `json:"comment"`
	Enabled      bool   `json:"enabled"`
}

// Conn 是一条活跃连接（会话表）。
type Conn struct {
	SrcIP   string
	DstIP   string
	DstPort int
	Proto   string
}

// Client 是爱快 API 客户端。
type Client struct {
	cfg *config.Config
	log *slog.Logger

	mu           sync.Mutex
	session      string
	loggedAt     time.Time
	banMode      string // 探测出的封禁方式：blacklist / acl / none
	probeTried   bool
	probeVariant banVariant // 探测成功的参数形态
}

func New(cfg *config.Config, log *slog.Logger) *Client {
	return &Client{cfg: cfg, log: log, banMode: ""}
}

func (c *Client) httpClient() *http.Client {
	timeout := 5
	_, _, t := c.cfg.IKuaiCreds()
	if t > 0 {
		timeout = t
	}
	return &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 爱快自签证书
		},
	}
}

// Login 登录并缓存 sess_key。同一 session 30 分钟内复用。
// 导出以便连接测试能强制重新登录。
//
// 兼容两种固件响应：
//   - 旧固件：{"Result":"<sess_key>","code":0}，sess_key 在 Result 字段
//   - 新固件：{"Result":10000,"code":0,"message":"成功"}，sess_key 由 Set-Cookie 返回
func (c *Client) Login(force bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.session != "" && time.Since(c.loggedAt) < 30*time.Minute {
		return nil
	}
	user, pass, _ := c.cfg.IKuaiCreds()
	md5sum := md5.Sum([]byte(pass))
	payload := map[string]string{
		"username": user,
		"passwd":   hex.EncodeToString(md5sum[:]),
		"pass":     base64.StdEncoding.EncodeToString([]byte("salt_113" + pass)),
	}
	body, _ := json.Marshal(payload)
	url := c.cfg.IKuaiBaseURL() + "/Action/login"
	resp, err := c.httpClient().Post(url, "application/json;charset=UTF-8", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("登录爱快失败: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)

	// Result 既可能是字符串（旧固件 sess_key），也可能是数字（新固件状态码），用 RawMessage 兼容
	var result struct {
		Result  json.RawMessage `json:"Result"`
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Errcode int             `json:"errcode"`
		SessKey string          `json:"sess_key"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("解析登录响应失败: %w (%s)", err, string(data))
	}
	if result.Code != 0 || result.Errcode != 0 {
		return fmt.Errorf("登录爱快失败(code=%d, errcode=%d): %s", result.Code, result.Errcode, result.Message)
	}

	// sess_key 来源优先级：Set-Cookie > JSON 字段 > Result 字符串
	sessKey := ""
	for _, ck := range resp.Cookies() {
		if strings.EqualFold(ck.Name, "sess_key") || strings.EqualFold(ck.Name, "sesskey") {
			sessKey = ck.Value
			break
		}
	}
	if sessKey == "" {
		sessKey = result.SessKey
	}
	if sessKey == "" && len(result.Result) > 0 {
		var s string
		if json.Unmarshal(result.Result, &s) == nil {
			sessKey = s
		}
	}
	if sessKey == "" {
		cookieNames := make([]string, 0, len(resp.Cookies()))
		for _, ck := range resp.Cookies() {
			cookieNames = append(cookieNames, ck.Name)
		}
		return fmt.Errorf("登录已成功但未获取到 sess_key，响应: %s，Cookie 字段: %v", string(data), cookieNames)
	}
	c.session = sessKey
	c.loggedAt = time.Now()
	c.log.Debug("爱快登录成功")
	return nil
}

// Call 调用爱快 API。action 通常为 show / add / del / edit。
func (c *Client) Call(funcName, action string, param map[string]any) (json.RawMessage, error) {
	if err := c.Login(false); err != nil {
		return nil, err
	}
	payload := map[string]any{"func_name": funcName, "action": action, "param": param}
	if param == nil {
		payload["param"] = map[string]any{}
	}
	body, _ := json.Marshal(payload)
	url := c.cfg.IKuaiBaseURL() + "/Action/call"

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ { // 登录过期时重试一次
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json;charset=UTF-8")
		user, _, _ := c.cfg.IKuaiCreds()
		c.mu.Lock()
		session := c.session
		c.mu.Unlock()
		req.Header.Set("Cookie", fmt.Sprintf("username=%s; sess_key=%s", user, session))
		resp, err := c.httpClient().Do(req)
		if err != nil {
			return nil, err
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
			continue
		}
		// 登录失效的典型响应
		if bytes.Contains(data, []byte("sess_key")) && bytes.Contains(data, []byte("fail")) {
			if err := c.Login(true); err != nil {
				return nil, err
			}
			continue
		}
		return data, nil
	}
	return nil, lastErr
}

// apiOK 判断爱快响应是否表示成功。兼容多种固件返回格式。
func apiOK(data json.RawMessage) bool {
	if len(data) == 0 {
		return false
	}
	var obj map[string]any
	if err := json.Unmarshal(data, &obj); err != nil {
		return false
	}
	for _, key := range []string{"code", "errcode", "ret", "errno"} {
		if v, ok := obj[key]; ok {
			switch n := v.(type) {
			case float64:
				if n != 0 {
					return false
				}
			case string:
				if n != "" && n != "0" && !strings.EqualFold(n, "success") {
					return false
				}
			case bool:
				if !n {
					return false
				}
			}
		}
	}
	return true
}

// extractRows 从各种响应形态中提取数组字段。
func extractRows(data json.RawMessage, keys ...string) []map[string]any {
	var obj map[string]any
	if json.Unmarshal(data, &obj) != nil {
		return nil
	}
	for _, key := range keys {
		if raw, ok := obj[key]; ok {
			switch v := raw.(type) {
			case []any:
				out := make([]map[string]any, 0, len(v))
				for _, item := range v {
					if m, ok := item.(map[string]any); ok {
						out = append(out, m)
					}
				}
				if len(out) > 0 {
					return out
				}
			case map[string]any:
				if rows, ok := v["data"].([]any); ok {
					out := make([]map[string]any, 0, len(rows))
					for _, item := range rows {
						if m, ok := item.(map[string]any); ok {
							out = append(out, m)
						}
					}
					if len(out) > 0 {
						return out
					}
				}
			}
		}
	}
	return nil
}

func num(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case json.Number:
		i, _ := n.Int64()
		return int(i)
	case string:
		var i int
		fmt.Sscanf(n, "%d", &i)
		return i
	}
	return 0
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// PortMappings 拉取端口映射规则。
func (c *Client) PortMappings() ([]Mapping, error) {
	data, err := c.Call("dnat", "show", map[string]any{"TYPE": "total,data", "limit": "0,500"})
	if err != nil {
		return nil, err
	}
	rows := extractRows(data, "data", "result", "results")
	out := make([]Mapping, 0, len(rows))
	for _, row := range rows {
		external := num(row["external_port"])
		if external == 0 {
			external = num(row["ext_port"])
		}
		if external == 0 {
			external = num(row["wan_port"])
		}
		internal := num(row["internal_port"])
		if internal == 0 {
			internal = num(row["int_port"])
		}
		if internal == 0 {
			internal = num(row["lan_port"])
		}
		if external == 0 || internal == 0 {
			continue
		}
		ip := str(row["internal_ip"])
		if ip == "" {
			ip = str(row["int_ip"])
		}
		proto := strings.ToLower(str(row["protocol"]))
		if proto != "udp" {
			proto = "tcp"
		}
		comment := str(row["comment"])
		if comment == "" {
			comment = str(row["tagname"])
		}
		enabled := true
		if v, ok := row["enabled"]; ok {
			enabled = str(v) == "yes" || num(v) == 1
		}
		out = append(out, Mapping{
			ID: num(row["id"]), ExternalPort: external, InternalPort: internal,
			InternalIP: ip, Protocol: proto, Comment: comment, Enabled: enabled,
		})
	}
	return out, nil
}

// Connections 拉取活跃连接表（可选功能，取决于固件是否支持）。
func (c *Client) Connections(funcName string) ([]Conn, error) {
	data, err := c.Call(funcName, "show", map[string]any{"TYPE": "data", "limit": "0,2000"})
	if err != nil {
		return nil, err
	}
	rows := extractRows(data, "data", "result", "results")
	out := make([]Conn, 0, len(rows))
	for _, row := range rows {
		src := str(row["src_ip"])
		if src == "" {
			src = str(row["srcip"])
		}
		if src == "" {
			src = str(row["sip"])
		}
		dst := str(row["dst_ip"])
		if dst == "" {
			dst = str(row["dstip"])
		}
		port := num(row["dst_port"])
		if port == 0 {
			port = num(row["dport"])
		}
		proto := strings.ToLower(str(row["protocol"]))
		if proto == "" {
			proto = strings.ToLower(str(row["proto"]))
		}
		if src == "" {
			continue
		}
		out = append(out, Conn{SrcIP: src, DstIP: dst, DstPort: port, Proto: proto})
	}
	return out, nil
}

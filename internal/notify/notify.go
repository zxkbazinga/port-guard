// Package notify 在新 IP 被封禁时向钉钉群机器人推送提醒。
// 发送走独立 worker，网络异常不会影响封禁链路。
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
)

const (
	queueSize      = 256
	requestTimeout = 5 * time.Second
)

// BanInfo 是一条封禁提醒的内容。
type BanInfo struct {
	IP      string
	Reason  string
	Rule    string
	Port    int
	Proto   string
	Minutes int
	Source  string // attack / geo_block / manual
}

// Notifier 钉钉通知器。配置每次发送时从 Config 读取，Web 保存后立即生效。
type Notifier struct {
	cfg     *config.Config
	log     *slog.Logger
	client  *http.Client
	country func(string) string
	queue   chan BanInfo
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.RWMutex // 保护队列关闭，避免退出时的残余告警写入已关闭通道
	stopped bool
	wg      sync.WaitGroup
	once    sync.Once
}

func New(cfg *config.Config, log *slog.Logger) *Notifier {
	ctx, cancel := context.WithCancel(context.Background())
	return &Notifier{
		cfg: cfg, log: log, client: &http.Client{Timeout: requestTimeout},
		queue: make(chan BanInfo, queueSize), ctx: ctx, cancel: cancel,
	}
}

// SetCountryLookup 注入可选的 IP 归属地查询（复用代理的地区索引，不重复加载数据）。
func (n *Notifier) SetCountryLookup(fn func(string) string) { n.country = fn }

func (n *Notifier) Start() {
	n.wg.Add(1)
	go n.loop()
}

// Stop 关闭队列并中断在途请求，保证进程退出不被钉钉网络拖住。
func (n *Notifier) Stop() {
	n.once.Do(func() {
		n.mu.Lock()
		n.stopped = true
		close(n.queue)
		n.mu.Unlock()
		n.cancel()
	})
	n.wg.Wait()
}

// Ban 把封禁提醒放入队列。队列满时丢弃，绝不阻塞封禁。
func (n *Notifier) Ban(info BanInfo) {
	if n == nil {
		return
	}
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.stopped {
		return
	}
	select {
	case n.queue <- info:
	default:
		n.log.Warn("钉钉通知队列已满，丢弃一条提醒", "ip", info.IP)
	}
}

func (n *Notifier) loop() {
	defer n.wg.Done()
	for info := range n.queue {
		if n.ctx.Err() != nil {
			return
		}
		if err := n.sendBan(n.ctx, info); err != nil {
			n.log.Warn("钉钉通知发送失败", "ip", info.IP, "err", err)
		}
	}
}

// Test 同步发送一条测试消息，返回钉钉接口的错误供 Web 页面展示。
func (n *Notifier) Test() error {
	return n.send(n.ctx, "Port Guard 通知测试",
		"### Port Guard 通知测试\n\n钉钉通知已配置成功。此后每次有新 IP 被封禁，都会在这里收到提醒。")
}

func (n *Notifier) sendBan(ctx context.Context, info BanInfo) error {
	title := "Port Guard 封禁提醒"
	var body strings.Builder
	body.WriteString("### Port Guard 封禁提醒\n\n")
	body.WriteString("- 来源 IP：**" + info.IP + "**")
	if n.country != nil {
		if country := n.country(info.IP); country != "" && country != "未知" {
			body.WriteString("（" + country + "）")
		}
	}
	body.WriteString("\n")
	if info.Rule != "" {
		body.WriteString("- 触发规则：" + info.Reason + "（" + info.Rule + "）\n")
	} else {
		body.WriteString("- 原因：" + info.Reason + "\n")
	}
	if info.Port > 0 {
		proto := info.Proto
		if proto == "" {
			proto = "tcp"
		}
		body.WriteString("- 目标端口：" + strconv.Itoa(info.Port) + "/" + proto + "\n")
	}
	if info.Minutes > 0 {
		body.WriteString("- 封禁时长：" + strconv.Itoa(info.Minutes) + " 分钟\n")
	} else {
		body.WriteString("- 封禁时长：永久\n")
	}
	body.WriteString("- 触发来源：" + banSourceName(info.Source) + "\n")
	body.WriteString("- 时间：" + time.Now().Format("2006-01-02 15:04:05") + "\n")
	return n.send(ctx, title, body.String())
}

func banSourceName(source string) string {
	switch source {
	case "geo_block":
		return "地区限制"
	case "manual":
		return "手工封禁"
	default:
		return "自动防护"
	}
}

// send 组装钉钉 markdown 消息；加签地址会附上 timestamp 与 sign。
func (n *Notifier) send(ctx context.Context, title, text string) error {
	s := n.cfg.DingTalk()
	if !s.Enabled {
		return nil
	}
	webhook := strings.TrimSpace(s.Webhook)
	if webhook == "" {
		return fmt.Errorf("未配置钉钉 Webhook 地址")
	}
	if keyword := strings.TrimSpace(s.Keyword); keyword != "" && !strings.Contains(text, keyword) {
		text = "[" + keyword + "] " + text
		if !strings.Contains(title, keyword) {
			title = "[" + keyword + "] " + title
		}
	}
	endpoint, err := signedURL(webhook, strings.TrimSpace(s.Secret))
	if err != nil {
		return err
	}
	payload, err := json.Marshal(map[string]any{
		"msgtype":  "markdown",
		"markdown": map[string]string{"title": title, "text": text},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("钉钉请求构造失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("钉钉请求失败: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("钉钉返回 HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var result struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if json.Unmarshal(data, &result) == nil && result.ErrCode != 0 {
		return fmt.Errorf("钉钉拒绝消息: %d %s", result.ErrCode, result.ErrMsg)
	}
	return nil
}

// signedURL 按钉钉加签规则生成 timestamp/sign 查询参数。
func signedURL(webhook, secret string) (string, error) {
	u, err := url.Parse(webhook)
	if err != nil {
		return "", fmt.Errorf("钉钉 Webhook 地址不合法: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("钉钉 Webhook 地址必须是 http(s) URL")
	}
	if secret == "" {
		return webhook, nil
	}
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(ts + "\n" + secret))
	// url.Values.Encode 会对 base64 中的 + / = 做一次正确的百分号编码。
	sign := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	q := u.Query()
	q.Set("timestamp", ts)
	q.Set("sign", sign)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

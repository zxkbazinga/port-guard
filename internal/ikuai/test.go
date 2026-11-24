package ikuai

import (
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
)

// TestParams 是"测试连接"使用的参数，仅存在于本次请求，不写入配置库。
type TestParams struct {
	Host     string
	Port     int
	SSL      bool
	Username string
	Password string
	Timeout  int
}

// TestStep 是一步诊断的结果。
type TestStep struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

// TestResult 是连接测试的完整结果，按步骤展示便于定位问题。
type TestResult struct {
	OK       bool       `json:"ok"`
	BaseURL  string     `json:"base_url"`
	Steps    []TestStep `json:"steps"`
	Mappings int        `json:"mappings"`
}

// TestConnection 分四步测试爱快 API：参数检查 → TCP 连通 → 登录 → 读取端口映射。
// 全程只读，不改变已有客户端的会话状态，也不持久化任何配置。
func TestConnection(p TestParams, log *slog.Logger) TestResult {
	if log == nil {
		log = slog.Default()
	}
	timeout := p.Timeout
	if timeout < 1 {
		timeout = 5
	}
	port := p.Port
	if port < 1 || port > 65535 {
		port = 80
	}
	scheme := "http"
	if p.SSL {
		scheme = "https"
	}
	addr := net.JoinHostPort(p.Host, strconv.Itoa(port))
	baseURL := scheme + "://" + addr

	r := TestResult{BaseURL: baseURL, Steps: make([]TestStep, 0, 4)}
	add := func(name string, ok bool, format string, args ...any) {
		r.Steps = append(r.Steps, TestStep{Name: name, OK: ok, Message: fmt.Sprintf(format, args...)})
	}
	fail := func(name, format string, args ...any) TestResult {
		add(name, false, format, args...)
		return r
	}

	// 1. 参数检查
	if strings.TrimSpace(p.Host) == "" {
		r.BaseURL = ""
		return fail("参数检查", "管理地址不能为空；容器bridge模式请填爱快的 LAN IP（例如 192.168.31.253），不要填 127.0.0.1")
	}
	if strings.TrimSpace(p.Username) == "" {
		return fail("参数检查", "用户名不能为空")
	}
	add("参数检查", true, "地址 %s，端口 %d，协议 %s，用户 %s", p.Host, port, scheme, p.Username)

	// 2. TCP 连通（先探端口，避免等满 HTTP 超时）
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeout)*time.Second)
	if err != nil {
		return fail("TCP 连通", "无法连接 %s：%v。请检查地址/端口是否正确、容器与爱快是否网络互通、HTTPS 是否勾选", addr, err)
	}
	_ = conn.Close()
	add("TCP 连通", true, "%s 可连接", addr)

	// 3. 登录（用临时配置，不动运行中的客户端）
	tmpCfg := config.NewEphemeral(config.Ephemeral{
		IKuaiHost: p.Host, IKuaiPort: port, IKuaiSSL: p.SSL,
		IKuaiUsername: p.Username, IKuaiPassword: p.Password, IKuaiTimeout: timeout,
	})
	client := New(tmpCfg, log)
	if err := client.Login(true); err != nil {
		return fail("爱快登录", "%v。常见原因：账号或密码错误、该账号无 API 权限、固件登录参数不兼容", err)
	}
	add("爱快登录", true, "登录成功，已获取 sess_key")

	// 4. 读取端口映射（登录成功即代表 API 可用；0 条映射不算失败）
	mappings, err := client.PortMappings()
	if err != nil {
		return fail("读取端口映射", "%v。登录正常，但调用 dnat 接口失败，可能是账号权限不足或固件接口不同", err)
	}
	msg := fmt.Sprintf("读取到 %d 条映射", len(mappings))
	if len(mappings) == 0 {
		msg += "（当前未配置端口映射，属正常情况）"
	}
	add("读取端口映射", true, "%s", msg)
	r.Mappings = len(mappings)

	r.OK = true
	return r
}

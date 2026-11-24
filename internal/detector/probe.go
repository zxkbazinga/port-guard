package detector

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ProbeRecord 是一次源 IP 探测的记录。
type ProbeRecord struct {
	Time string `json:"time"`
	IP   string `json:"ip"`
	Port string `json:"port"`
}

// SourceProbe 是一个纯诊断端点：在固定端口回显它看到的来源 IP。
// 用途是验证爱快端口映射是否把公网客户端的真实 IP 透传到容器。
// 它不接入检测引擎、不封禁、不写库，只是把观测结果记在内存里并在 Web 展示。
type SourceProbe struct {
	log     *slog.Logger
	port    int
	ln      net.Listener
	mu      sync.Mutex
	records []ProbeRecord
	hits    atomic.Uint64
	running atomic.Bool
}

func NewSourceProbe(log *slog.Logger, port int) *SourceProbe {
	return &SourceProbe{log: log, port: port}
}

func (p *SourceProbe) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p.port))
	if err != nil {
		return err
	}
	p.ln = ln
	p.running.Store(true)
	p.log.Info("源 IP 探测端点已启动", "port", p.port)
	go p.serve(ln)
	return nil
}

func (p *SourceProbe) serve(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if p.running.Load() {
				p.log.Warn("源 IP 探测监听结束", "err", err)
			}
			return
		}
		go p.handle(conn)
	}
}

func (p *SourceProbe) handle(conn net.Conn) {
	defer conn.Close()
	ip, port := "unknown", ""
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		ip = addr.IP.String()
		port = fmt.Sprint(addr.Port)
	}
	p.hits.Add(1)
	p.mu.Lock()
	p.records = append([]ProbeRecord{{Time: time.Now().Format("2006-01-02 15:04:05"), IP: ip, Port: port}}, p.records...)
	if len(p.records) > 20 {
		p.records = p.records[:20]
	}
	p.mu.Unlock()
	p.log.Info("源 IP 探测命中", "ip", ip, "port", port)

	// 读掉客户端的请求（浏览器 / nc 都兼容），避免直接关闭时发 RST 丢响应。
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = bufio.NewReader(conn).ReadString('\n')
	_ = conn.SetWriteDeadline(time.Now().Add(3 * time.Second))

	body := fmt.Sprintf("port-guard 源 IP 探测\n\n来源 IP : %s\n来源端口: %s\n时间    : %s\n\n"+
		"如果这里显示的是公网 IP，说明爱快端口映射保留了真实源地址，代理方案可行。\n"+
		"如果显示的是爱快 LAN IP（如 192.168.x.x），说明源地址被改写，代理方案拿不到真实客户端 IP。\n",
		ip, port, time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"+
		"Content-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
}

func (p *SourceProbe) Stop() {
	p.running.Store(false)
	if p.ln != nil {
		_ = p.ln.Close()
	}
}

// Stats 返回探测状态与最近记录。
func (p *SourceProbe) Stats() map[string]any {
	p.mu.Lock()
	records := append([]ProbeRecord(nil), p.records...)
	p.mu.Unlock()
	return map[string]any{
		"running": p.running.Load(),
		"port":    p.port,
		"hits":    p.hits.Load(),
		"records": records,
	}
}

// Package proxy 实现串联式 TCP 反向代理：爱快把外网端口映射到本应用的监听端口，
// 代理在 accept 阶段做白名单/封禁判定，再把连接转发到内网真实服务。
// 由于流量必经代理，封禁在 accept 阶段本地即时生效，不依赖任何外部 API。
package proxy

import (
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/detector"
	"github.com/zxkbazinga/port-guard/internal/store"
)

// ConnRecord 是一条最近连接记录。
type ConnRecord struct {
	Time     string `json:"time"`
	IP       string `json:"ip"`
	Listen   int    `json:"listen"`
	Backend  string `json:"backend"`
	Action   string `json:"action"`
	Duration string `json:"duration"`
}

// Server 管理所有转发监听器。
type Server struct {
	cfg   *config.Config
	log   *slog.Logger
	eng   *detector.Engine
	store *store.Store

	mu        sync.Mutex
	listeners map[int]net.Listener // listenPort -> listener
	closed    map[int]bool         // Reload 时标记旧监听器，避免误报日志
	records   []ConnRecord
	localBan  map[string]int64 // IP -> 到期 Unix 秒；本地封禁，不依赖爱快 API
	running   atomic.Bool

	total   atomic.Uint64
	blocked atomic.Uint64
	active  atomic.Int64
	bytes   atomic.Uint64
}

func New(cfg *config.Config, log *slog.Logger, eng *detector.Engine, s *store.Store) *Server {
	return &Server{cfg: cfg, log: log, eng: eng, store: s,
		listeners: make(map[int]net.Listener), closed: make(map[int]bool),
		localBan: make(map[string]int64)}
}

// Block 本地封禁 IP 指定分钟。由检测告警回调直接调用，不依赖爱快 API。
// minutes <= 0 时使用全局封禁时长，与 ban.Manager 保持一致。
func (p *Server) Block(ip string, minutes int) {
	if ip == "" {
		return
	}
	if minutes <= 0 {
		minutes = p.cfg.BanMinutes()
	}
	if minutes <= 0 {
		minutes = 30 // 兜底
	}
	until := time.Now().Add(time.Duration(minutes) * time.Minute).Unix()
	p.mu.Lock()
	p.localBan[ip] = until
	p.mu.Unlock()
	p.log.Info("代理本地封禁已生效", "ip", ip, "minutes", minutes)
}

// Unblock 解除本地封禁。
func (p *Server) Unblock(ip string) {
	p.mu.Lock()
	delete(p.localBan, ip)
	p.mu.Unlock()
}

func (p *Server) isLocallyBanned(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	until, ok := p.localBan[ip]
	if !ok {
		return false
	}
	if until <= time.Now().Unix() {
		delete(p.localBan, ip)
		return false
	}
	return true
}

// Reload 按当前配置重建所有监听器。配置变更后调用。
func (p *Server) Reload() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 关闭所有旧监听器
	for port, ln := range p.listeners {
		p.closed[port] = true
		_ = ln.Close()
	}
	p.listeners = make(map[int]net.Listener)

	// 清理已过期的本地封禁，防止内存无限增长
	now := time.Now().Unix()
	for ip, until := range p.localBan {
		if until <= now {
			delete(p.localBan, ip)
		}
	}

	if !p.cfg.ProxyEnabled() {
		p.running.Store(false)
		return nil
	}
	forwards, err := p.store.ListForwards(true)
	if err != nil {
		return err
	}
	for _, f := range forwards {
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(f.ListenPort))
		if err != nil {
			p.log.Warn("转发监听失败", "port", f.ListenPort, "err", err)
			continue
		}
		p.listeners[f.ListenPort] = ln
		p.log.Info("转发监听已启动", "listen", f.ListenPort,
			"backend", net.JoinHostPort(f.BackendIP, strconv.Itoa(f.BackendPort)), "label", f.Label)
		go p.serve(ln, f)
	}
	p.running.Store(len(p.listeners) > 0)
	return nil
}

func (p *Server) serve(ln net.Listener, f store.Forward) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			p.mu.Lock()
			expected := p.closed[f.ListenPort]
			p.mu.Unlock()
			if !expected && p.running.Load() {
				p.log.Warn("转发监听结束", "port", f.ListenPort, "err", err)
			}
			return
		}
		go p.handle(conn, f)
	}
}

func (p *Server) handle(conn net.Conn, f store.Forward) {
	defer conn.Close()
	start := time.Now()
	p.total.Add(1)

	srcIP := ""
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		srcIP = addr.IP.String()
	}
	backend := net.JoinHostPort(f.BackendIP, strconv.Itoa(f.BackendPort))

	// 1) 白名单/私网：保护名单直接放行，不做攻击判定
	if srcIP != "" && p.cfg.IsProtected(srcIP) {
		p.forward(conn, backend, srcIP, f, start, "白名单放行")
		return
	}

	// 2) 已封禁 IP：本地封禁表优先（告警回调直接写入），
	//    其次查数据库里的封禁记录（手工封禁 / 引擎告警封禁）。
	if srcIP != "" && p.isLocallyBanned(srcIP) {
		p.blocked.Add(1)
		p.record(start, srcIP, f, backend, "本地封禁拒绝", time.Since(start))
		p.log.Info("代理本地拦截封禁 IP", "ip", srcIP, "listen", f.ListenPort)
		return
	}
	if srcIP != "" {
		if b, err := p.store.GetBan(srcIP); err == nil && b != nil && b.Active && b.ExpiresAt > time.Now().Unix() {
			p.blocked.Add(1)
			p.record(start, srcIP, f, backend, "封禁拒绝", time.Since(start))
			p.log.Info("代理拦截已封禁 IP", "ip", srcIP, "listen", f.ListenPort)
			return
		}
	}

	// 3) 送检测引擎：连接频率 / 多端口扫描等规则在此判定
	if srcIP != "" {
		if p.eng.Feed(detector.Observation{
			Kind: detector.KindConn, IP: srcIP, Port: f.ListenPort, Proto: "tcp",
			Detail: "代理转发 " + f.Label,
		}) {
			// 引擎已判定攻击：本次连接也不放行（告警回调会同步写入封禁记录）
			p.blocked.Add(1)
			p.record(start, srcIP, f, backend, "检测拦截", time.Since(start))
			p.log.Warn("代理拦截攻击连接", "ip", srcIP, "listen", f.ListenPort)
			return
		}
	}

	p.forward(conn, backend, srcIP, f, start, "转发")
}

func (p *Server) forward(conn net.Conn, backend string, srcIP string, f store.Forward, start time.Time, action string) {
	upstream, err := net.DialTimeout("tcp", backend, 5*time.Second)
	if err != nil {
		p.record(start, srcIP, f, backend, "后端不可达", time.Since(start))
		p.log.Warn("转发后端不可达", "listen", f.ListenPort, "backend", backend, "err", err)
		return
	}
	defer upstream.Close()
	p.active.Add(1)
	defer p.active.Add(-1)

	// NoDelay 减少小包延迟（SSH/RDP 交互场景）
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	if tc, ok := upstream.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	pump := func(dst, src net.Conn) {
		defer wg.Done()
		n, err := io.Copy(dst, src)
		p.bytes.Add(uint64(n))
		if err != nil {
			return
		}
		// 半关闭：让对端读完剩余数据
		if c, ok := dst.(*net.TCPConn); ok {
			_ = c.CloseWrite()
		}
	}
	go pump(upstream, conn)
	go pump(conn, upstream)
	wg.Wait()
	p.record(start, srcIP, f, backend, action, time.Since(start))
}

func (p *Server) record(start time.Time, ip string, f store.Forward, backend, action string, d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.records = append([]ConnRecord{{
		Time:     start.Format("2006-01-02 15:04:05"),
		IP:       ip,
		Listen:   f.ListenPort,
		Backend:  backend,
		Action:   action,
		Duration: d.Round(time.Millisecond).String(),
	}}, p.records...)
	if len(p.records) > 30 {
		p.records = p.records[:30]
	}
}

func (p *Server) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for port, ln := range p.listeners {
		p.closed[port] = true
		_ = ln.Close()
	}
	p.listeners = make(map[int]net.Listener)
	p.running.Store(false)
}

// Stats 返回代理运行状态与最近连接。
func (p *Server) Stats() map[string]any {
	p.mu.Lock()
	ports := make([]int, 0, len(p.listeners))
	for port := range p.listeners {
		ports = append(ports, port)
	}
	records := append([]ConnRecord(nil), p.records...)
	p.mu.Unlock()
	return map[string]any{
		"running": p.running.Load(),
		"enabled": p.cfg.ProxyEnabled(),
		"ports":   ports,
		"total":   p.total.Load(),
		"blocked": p.blocked.Load(),
		"active":  p.active.Load(),
		"bytes":   p.bytes.Load(),
		"records": records,
	}
}

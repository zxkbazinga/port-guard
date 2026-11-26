// Package proxy 实现串联式 TCP 反向代理：爱快把外网端口映射到本应用的监听端口，
// 代理在 accept 阶段做白名单/封禁判定，再把连接转发到内网真实服务。
// 由于流量必经代理，封禁在 accept 阶段本地即时生效，不依赖任何外部 API。
package proxy

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/detector"
	"github.com/zxkbazinga/port-guard/internal/geoip"
	"github.com/zxkbazinga/port-guard/internal/store"
)

// maxConnRecords 是内存中保留的转发日志上限。
const maxConnRecords = 1000

// 短连接判定阈值：持续时间与双向传输字节数均低于阈值即视为一次"空连接"。
// SSH/MySQL/RDP 爆破的典型特征是连上后只交换认证包（数 KB）便断开，
// 而正常用户在建立连接后会有持续的数据传输或长连接保持。
const (
	shortConnMaxDuration = 3 * time.Second
	shortConnMaxBytes    = 8192
)

// ConnRecord 是一条最近连接记录。
type ConnRecord struct {
	ID       uint64 `json:"id"`
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
	geo   *geoip.Checker
	store *store.Store

	mu        sync.Mutex
	listeners map[int]net.Listener // listenPort -> listener
	closed    map[int]bool         // Reload 时标记旧监听器，避免误报日志
	// 转发日志用固定容量环形缓冲，避免每条连接都整体复制切片产生 O(n) 拷贝与 GC 压力。
	recBuf   [maxConnRecords]ConnRecord
	recHead  int              // 下一条写入的槽位
	recLen   int              // 当前有效条数
	recIdx   map[uint64]int   // 记录 ID -> 槽位，供耗时回填 O(1) 定位
	localBan map[string]int64 // IP -> 到期 Unix 秒；本地封禁，不依赖爱快 API
	running  atomic.Bool

	total   atomic.Uint64
	blocked atomic.Uint64
	active  atomic.Int64
	bytes   atomic.Uint64
	recSeq  atomic.Uint64
}

func New(cfg *config.Config, log *slog.Logger, eng *detector.Engine, s *store.Store) *Server {
	geo, err := geoip.New()
	if err != nil {
		log.Error("地区限制数据加载失败，转发端口将不按来源地区拦截", "err", err)
		geo = nil
	}
	return &Server{cfg: cfg, log: log, eng: eng, geo: geo, store: s,
		listeners: make(map[int]net.Listener), closed: make(map[int]bool),
		recIdx: make(map[uint64]int), localBan: make(map[string]int64)}
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
	// 只有存在 TLS 终结规则时才要求证书文件存在，避免纯 TCP 用户被证书配置卡住。
	var tlsCfg *tls.Config
	for _, f := range forwards {
		if f.ListenTLS {
			tlsCfg, err = p.loadTLSConfig()
			if err != nil {
				p.log.Warn("TLS 证书加载失败，入口 HTTPS 规则将跳过", "err", err)
				tlsCfg = nil
			}
			break
		}
	}
	for _, f := range forwards {
		rawLn, err := net.Listen("tcp", ":"+strconv.Itoa(f.ListenPort))
		if err != nil {
			p.log.Warn("转发监听失败", "port", f.ListenPort, "err", err)
			continue
		}
		var ln net.Listener = rawLn
		if f.ListenTLS {
			if tlsCfg == nil {
				_ = rawLn.Close()
				p.log.Warn("跳过 TLS 规则：证书不可用", "port", f.ListenPort)
				continue
			}
			ln = tls.NewListener(rawLn, tlsCfg)
		}
		p.listeners[f.ListenPort] = ln
		p.log.Info("转发监听已启动", "listen", f.ListenPort,
			"backend", net.JoinHostPort(f.BackendIP, strconv.Itoa(f.BackendPort)),
			"listen_tls", f.ListenTLS, "backend_tls", f.BackendTLS, "label", f.Label)
		go p.serve(ln, f)
	}
	p.running.Store(len(p.listeners) > 0)
	return nil
}

// loadTLSConfig 从配置指定的 PEM 文件加载证书与私钥。
func (p *Server) loadTLSConfig() (*tls.Config, error) {
	certFile, keyFile := p.cfg.TLSFiles()
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// prepareFrontend 完成入口侧 TLS 握手。非 TLS 规则原样返回连接。
func (p *Server) prepareFrontend(conn net.Conn, f store.Forward, start time.Time, srcIP, backend string) (net.Conn, bool) {
	if !f.ListenTLS {
		return conn, true
	}
	tc, ok := conn.(*tls.Conn)
	if !ok {
		p.record(start, srcIP, f, backend, "TLS配置错误", time.Since(start))
		p.log.Warn("TLS 规则收到非 TLS 连接", "listen", f.ListenPort)
		return nil, false
	}
	_ = tc.SetReadDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		p.record(start, srcIP, f, backend, "TLS握手失败", time.Since(start))
		p.log.Warn("入口 TLS 握手失败", "listen", f.ListenPort, "ip", srcIP, "err", err)
		return nil, false
	}
	_ = tc.SetReadDeadline(time.Time{})
	return tc, true
}

// dialBackend 建立到后端的连接；如规则启用后端 TLS，直接用后端 IP 发起 TLS。
// 内网 HTTPS 多为自签证书且只有 IP、没有域名，因此跳过服务端证书校验，
// 只借助 TLS 加密链路；ServerName 设为后端 IP 以兼容要求 SNI 的服务端。
func (p *Server) dialBackend(f store.Forward, backend string) (net.Conn, error) {
	if !f.BackendTLS {
		return net.DialTimeout("tcp", backend, 5*time.Second)
	}
	return tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", backend,
		&tls.Config{ServerName: f.BackendIP, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // #nosec G402 -- 内网 IP + 自签证书场景
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

	// 2) 来源地区限制：仅对公网 IP 生效；白名单/私网已在上面放行。
	if srcIP != "" && p.geo != nil && !p.geo.Allows(srcIP, p.cfg.GeoMode()) {
		p.blocked.Add(1)
		p.record(start, srcIP, f, backend, "地区限制拒绝", time.Since(start))
		p.log.Info("代理拦截非允许地区 IP", "ip", srcIP, "listen", f.ListenPort, "mode", p.cfg.GeoMode())
		return
	}

	// 3) 已封禁 IP：本地封禁表优先（告警回调直接写入），
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

	// 4) 送检测引擎：连接频率 / 多端口扫描等规则在此判定
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
	frontend, ok := p.prepareFrontend(conn, f, start, srcIP, backend)
	if !ok {
		return
	}
	conn = frontend
	upstream, err := p.dialBackend(f, backend)
	if err != nil {
		p.record(start, srcIP, f, backend, "后端不可达", time.Since(start))
		p.log.Warn("转发后端不可达", "listen", f.ListenPort, "backend", backend, "err", err)
		return
	}
	defer upstream.Close()
	p.active.Add(1)
	defer p.active.Add(-1)

	// 连接一建立就写日志，长连接（HTTPS/SSH）也能立刻在页面看到
	recID := p.record(start, srcIP, f, backend, action, 0)

	// NoDelay 减少小包延迟（SSH/RDP 交互场景）
	setNoDelay(conn)
	setNoDelay(upstream)

	var wg sync.WaitGroup
	wg.Add(2)
	var connBytes atomic.Uint64 // 本连接的双向传输字节数，用于短连接判定
	pump := func(dst, src net.Conn) {
		defer wg.Done()
		n, err := io.Copy(dst, src)
		p.bytes.Add(uint64(n))
		connBytes.Add(uint64(n))
		if err != nil {
			// 任一方向异常时立即关闭两端，避免另一方向的 io.Copy 永久阻塞
			_ = conn.Close()
			_ = upstream.Close()
			return
		}
		// 半关闭：让对端读完剩余数据
		closeWrite(dst)
	}
	go pump(upstream, conn)
	go pump(conn, upstream)
	wg.Wait()
	elapsed := time.Since(start)
	p.finishRecord(recID, elapsed)

	// 短连接判定：只对公网 IP 生效（白名单/私网在 handle 阶段已放行），
	// 且检测总开关开启、有源 IP 时才统计。命中后由引擎累计，超阈值再封禁。
	if srcIP != "" && !p.cfg.IsProtected(srcIP) && p.cfg.DetectionEnabled() &&
		elapsed < shortConnMaxDuration && connBytes.Load() < shortConnMaxBytes {
		p.eng.Feed(detector.Observation{
			Kind: detector.KindShortConn, IP: srcIP, Port: f.ListenPort, Proto: "tcp",
			Detail: "低流量短连接 " + elapsed.Round(time.Millisecond).String() + " / " +
				strconv.FormatUint(connBytes.Load(), 10) + "B",
		})
	}
}

// setNoDelay 对 TCP 连接及 TLS 包装下的底层 TCP 连接关闭 Nagle 算法。
func setNoDelay(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		return
	}
	if wrapper, ok := c.(interface{ NetConn() net.Conn }); ok {
		setNoDelay(wrapper.NetConn())
	}
}

// closeWrite 对 TCP 连接及 TLS 包装下的底层 TCP 连接做半关闭。
func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
		return
	}
	if wrapper, ok := c.(interface{ NetConn() net.Conn }); ok {
		closeWrite(wrapper.NetConn())
	}
}

// record 立即写入一条日志并返回其 ID，便于连接关闭后回填耗时。
// 环形缓冲写入为 O(1)：覆盖最旧一条时同步清理其 ID 索引。
func (p *Server) record(start time.Time, ip string, f store.Forward, backend, action string, d time.Duration) uint64 {
	id := p.recSeq.Add(1)
	duration := "连接中"
	if d > 0 {
		duration = d.Round(time.Millisecond).String()
	}
	rec := ConnRecord{
		ID:       id,
		Time:     start.Format("2006-01-02 15:04:05"),
		IP:       ip,
		Listen:   f.ListenPort,
		Backend:  backend,
		Action:   action,
		Duration: duration,
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.recLen == maxConnRecords {
		// 即将覆盖的最旧一条，先从索引移除
		delete(p.recIdx, p.recBuf[p.recHead].ID)
	} else {
		p.recLen++
	}
	p.recBuf[p.recHead] = rec
	p.recIdx[id] = p.recHead
	p.recHead = (p.recHead + 1) % maxConnRecords
	return id
}

// finishRecord 在连接结束后把「连接中」替换为真实耗时（通过 ID 索引 O(1) 定位）。
func (p *Server) finishRecord(id uint64, d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if slot, ok := p.recIdx[id]; ok {
		p.recBuf[slot].Duration = d.Round(time.Millisecond).String()
	}
}

// Records 返回最近的转发日志（最新在前）。limit<=0 表示最多返回全部 1000 条。
func (p *Server) Records(limit int) []ConnRecord {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := p.recLen
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]ConnRecord, n)
	for i := 0; i < n; i++ {
		slot := (p.recHead - 1 - i + maxConnRecords) % maxConnRecords
		out[i] = p.recBuf[slot]
	}
	return out
}

// ClearRecords 手动清空内存中的转发日志。
func (p *Server) ClearRecords() {
	p.mu.Lock()
	p.recBuf = [maxConnRecords]ConnRecord{}
	p.recHead = 0
	p.recLen = 0
	p.recIdx = make(map[uint64]int)
	p.mu.Unlock()
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
	// 概览页只需要少量记录，完整日志走 /api/forwards/logs
	records := p.Records(30)
	p.mu.Lock()
	ports := make([]int, 0, len(p.listeners))
	for port := range p.listeners {
		ports = append(ports, port)
	}
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

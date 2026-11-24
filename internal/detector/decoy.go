package detector

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"github.com/zxkbazinga/port-guard/internal/config"
)

// DecoyListener 监听一组“诱饵端口”：这些端口不承载任何服务，
// 由爱快把 WAN 侧对应端口 DNAT 到本容器。任何成功建立的连接都视为扫描行为。
//
// 它不依赖爱快连接表 API（V4 固件不提供）或 syslog 日志内容，
// 是桥接部署下可靠的高置信度检测源。
type DecoyListener struct {
	cfg       *config.Config
	log       *slog.Logger
	eng       *Engine
	mu        sync.Mutex
	listeners []net.Listener
	running   atomic.Bool
	hits      atomic.Uint64
	portCount int
}

func NewDecoyListener(cfg *config.Config, log *slog.Logger, eng *Engine) *DecoyListener {
	return &DecoyListener{cfg: cfg, log: log, eng: eng}
}

// Start 按当前配置启动诱饵端口监听。
func (d *DecoyListener) Start() error {
	return d.Reload()
}

// Reload 用最新配置重建监听（配置页保存后调用）。
func (d *DecoyListener) Reload() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopLocked()

	if !d.cfg.DecoyEnabled() {
		return nil
	}
	ports := d.cfg.DecoyPorts()
	for _, p := range ports {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
		if err != nil {
			d.log.Warn("诱饵端口监听失败", "port", p, "err", err)
			continue
		}
		d.listeners = append(d.listeners, ln)
		d.log.Info("诱饵端口已监听", "port", p)
		go d.serve(ln, p)
	}
	d.running.Store(len(d.listeners) > 0)
	d.portCount = len(d.listeners)
	return nil
}

func (d *DecoyListener) serve(ln net.Listener, port int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if d.running.Load() {
				d.log.Debug("诱饵端口监听结束", "port", port, "err", err)
			}
			return
		}
		ip := ""
		if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			ip = addr.IP.String()
		}
		_ = conn.Close() // 不提供任何服务，立刻断开
		d.hits.Add(1)
		if ip == "" {
			continue
		}
		d.eng.Feed(Observation{
			Kind: KindDecoy, IP: ip, Port: port, Proto: "tcp",
			Detail: "命中诱饵端口 " + fmt.Sprint(port),
		})
	}
}

func (d *DecoyListener) stopLocked() {
	d.running.Store(false)
	for _, ln := range d.listeners {
		_ = ln.Close()
	}
	d.listeners = nil
	d.portCount = 0
}

// Stop 关闭全部诱饵端口监听。
func (d *DecoyListener) Stop() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopLocked()
}

// Stats 返回状态供 Web 展示。
func (d *DecoyListener) Stats() map[string]any {
	d.mu.Lock()
	ports := d.portCount
	d.mu.Unlock()
	return map[string]any{
		"running": d.running.Load(),
		"ports":   ports,
		"hits":    d.hits.Load(),
	}
}

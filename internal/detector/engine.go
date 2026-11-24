// Package detector 实现攻击检测引擎。
//
// 所有检测源（抓包、Syslog、爱快连接表轮询）统一把观测事件喂给 Engine，
// Engine 用滑动窗口统计每个源 IP 的行为，命中规则后回调上层执行封禁。
package detector

import (
	"container/list"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
)

// Kind 是观测事件的类型。
type Kind int

const (
	KindSYN    Kind = iota // TCP SYN（新建连接尝试）
	KindUDP                // UDP 包
	KindConn               // 来自爱快连接表的新建连接
	KindSyslog             // 来自爱快安全日志的告警
)

// Observation 是一次观测。
type Observation struct {
	Kind   Kind
	IP     string
	Port   int
	Proto  string
	Detail string
	TS     time.Time
}

// Alert 是检测引擎判定的攻击告警。
type Alert struct {
	IP       string
	Port     int
	Proto    string
	Rule     string // syn_flood / port_scan / conn_rate / udp_flood / syslog
	Reason   string
	Detail   string
	Evidence string
}

// ipState 保存单个源 IP 的滑动窗口数据。
type ipState struct {
	hits      *list.List // []hit{ts, port}
	ports     map[int]int
	lastAlert time.Time
	alertRule string
}

type hit struct {
	ts   time.Time
	port int
	kind Kind
}

// Engine 是并发安全的检测引擎。
type Engine struct {
	mu      sync.Mutex
	cfg     *config.Config
	log     *slog.Logger
	states  map[string]*ipState
	onAlert func(Alert)
	known   map[int]bool // 当前监控的端口集合，用于过滤非映射端口的流量
}

func New(cfg *config.Config, log *slog.Logger, onAlert func(Alert)) *Engine {
	e := &Engine{
		cfg: cfg, log: log, onAlert: onAlert,
		states: make(map[string]*ipState), known: make(map[int]bool),
	}
	go e.janitor()
	return e
}

// SetPorts 更新监控端口集合。传 nil 表示不过滤（全部端口都检测）。
func (e *Engine) SetPorts(ports []int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.known = make(map[int]bool, len(ports))
	for _, p := range ports {
		e.known[p] = true
	}
}

// Feed 接收一条观测事件。返回是否产生了告警。
func (e *Engine) Feed(o Observation) bool {
	if o.IP == "" || o.TS.IsZero() {
		o.TS = time.Now()
	}
	if e.cfg.IsProtected(o.IP) {
		return false
	}
	if !e.cfg.DetectionEnabled() {
		return false
	}

	// 端口映射过滤：只有发往映射端口的流量才计入（syslog 事件除外）
	if o.Kind != KindSyslog && len(e.known) > 0 && !e.known[o.Port] {
		return false
	}

	e.mu.Lock()
	state, ok := e.states[o.IP]
	if !ok {
		state = &ipState{hits: list.New(), ports: make(map[int]int)}
		e.states[o.IP] = state
	}
	state.hits.PushBack(hit{ts: o.TS, port: o.Port, kind: o.Kind})
	if o.Port > 0 {
		state.ports[o.Port]++
	}
	th := e.cfg.Thresholds()
	alert := e.evaluate(o.IP, state, o, th)
	e.mu.Unlock()

	if alert != nil && e.onAlert != nil {
		e.onAlert(*alert)
		return true
	}
	return false
}

// evaluate 在持锁状态下检查四条规则。返回优先级最高的命中告警。
func (e *Engine) evaluate(ip string, state *ipState, o Observation, th config.Thresholds) *Alert {
	now := o.TS
	cutoff := now.Add(-time.Duration(th.Window) * time.Second)

	// 清理窗口外的数据
	for front := state.hits.Front(); front != nil; front = state.hits.Front() {
		h := front.Value.(hit)
		if h.ts.After(cutoff) {
			break
		}
		state.hits.Remove(front)
		state.ports[h.port]--
		if state.ports[h.port] <= 0 {
			delete(state.ports, h.port)
		}
	}

	// 冷却期内不重复告警
	if now.Sub(state.lastAlert) < time.Duration(th.Cooldown)*time.Second {
		return nil
	}

	var result *Alert
	synOnPort, udpCount, connCount := 0, 0, 0
	for node := state.hits.Front(); node != nil; node = node.Next() {
		h := node.Value.(hit)
		switch h.kind {
		case KindSYN:
			if h.port == o.Port {
				synOnPort++
			}
		case KindUDP:
			udpCount++
		case KindConn:
			connCount++
		}
	}

	if o.Kind == KindSyslog {
		result = &Alert{IP: ip, Port: o.Port, Proto: o.Proto, Rule: "syslog",
			Reason: "爱快安全日志告警", Detail: o.Detail}
	}

	switch {
	case result != nil:
	case o.Kind == KindSYN && synOnPort >= th.SynFlood:
		result = &Alert{IP: ip, Port: o.Port, Proto: "tcp", Rule: "syn_flood",
			Reason: "SYN Flood 攻击", Detail: "窗口内对同一端口的 SYN 数量异常",
			Evidence: "syn=" + strconv.Itoa(synOnPort) + "/" + strconv.Itoa(th.SynFlood)}
	case len(state.ports) >= th.PortScan:
		ports := make([]string, 0, len(state.ports))
		for p := range state.ports {
			ports = append(ports, strconv.Itoa(p))
		}
		result = &Alert{IP: ip, Rule: "port_scan", Reason: "端口扫描行为",
			Detail:   "短时间内探测多个不同端口",
			Evidence: "ports=" + strings.Join(ports, ",") + " (" + strconv.Itoa(len(state.ports)) + ")"}
	case udpCount >= th.UDPFlood:
		result = &Alert{IP: ip, Port: o.Port, Proto: "udp", Rule: "udp_flood",
			Reason: "UDP Flood 攻击", Detail: "窗口内 UDP 包数量异常",
			Evidence: "udp=" + strconv.Itoa(udpCount) + "/" + strconv.Itoa(th.UDPFlood)}
	case connCount >= th.ConnRate:
		result = &Alert{IP: ip, Rule: "conn_rate", Reason: "连接频率异常",
			Detail:   "窗口内新建连接数超过阈值",
			Evidence: "conn=" + strconv.Itoa(connCount) + "/" + strconv.Itoa(th.ConnRate)}
	}

	if result != nil {
		state.lastAlert = now
		state.alertRule = result.Rule
		// 告警后清空窗口，避免同一批流量连续触发
		state.hits.Init()
		state.ports = make(map[int]int)
	}
	return result
}

// janitor 定期清理长时间不活跃的 IP 状态，防止内存无限增长。
func (e *Engine) janitor() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		e.mu.Lock()
		cutoff := time.Now().Add(-30 * time.Minute)
		for ip, state := range e.states {
			if state.lastAlert.Before(cutoff) && (state.hits.Len() == 0 || state.hits.Back().Value.(hit).ts.Before(cutoff)) {
				delete(e.states, ip)
			}
		}
		e.mu.Unlock()
	}
}

// Reset 清空所有状态（配置变更后调用）。
func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.states = make(map[string]*ipState)
}

// Stats 返回引擎当前状态（供 Web 展示）。
func (e *Engine) Stats() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	return map[string]any{
		"tracked_ips":     len(e.states),
		"monitored_ports": len(e.known),
	}
}

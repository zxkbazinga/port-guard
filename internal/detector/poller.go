package detector

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/ikuai"
	"github.com/zxkbazinga/port-guard/internal/store"
)

// Poller 定期从爱快 API 拉取端口映射与连接表。
// 连接表轮询是抓包不可用时的主力检测源。
type Poller struct {
	cfg            *config.Config
	log            *slog.Logger
	eng            *Engine
	client         *ikuai.Client
	store          *store.Store
	running        atomic.Bool
	cancel         context.CancelFunc
	portsRefreshed atomic.Uint64
	connsPolled    atomic.Uint64
}

func NewPoller(cfg *config.Config, log *slog.Logger, eng *Engine, client *ikuai.Client, s *store.Store) *Poller {
	return &Poller{cfg: cfg, log: log, eng: eng, client: client, store: s}
}

func (p *Poller) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.running.Store(true)
	go p.run(ctx)
}

func (p *Poller) run(ctx context.Context) {
	// 启动时立即拉取一次
	p.RefreshPorts()
	p.pollConns()

	portTicker := time.NewTicker(time.Duration(p.cfg.PortRefreshInterval()) * time.Second)
	connTicker := time.NewTicker(time.Duration(p.cfg.ConnPollInterval()) * time.Second)
	defer portTicker.Stop()
	defer connTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-portTicker.C:
			if p.cfg.PortRefreshEnabled() {
				p.RefreshPorts()
			}
		case <-connTicker.C:
			if p.cfg.ConnPollEnabled() {
				p.pollConns()
			}
		}
	}
}

// RefreshPorts 从爱快拉取端口映射并写入数据库，同时更新检测引擎的端口集合。
// 导出以便在配置变更、测试连接成功后立即同步，不必等定时周期。
// 返回本次同步的映射条数；失败时保留原有端口数据。
func (p *Poller) RefreshPorts() (int, error) {
	mappings, err := p.client.PortMappings()
	if err != nil {
		p.log.Warn("拉取爱快端口映射失败", "err", err)
		return 0, err
	}
	if len(mappings) == 0 {
		return 0, nil
	}
	// 保留手工添加的端口，清除上次从爱快同步的端口
	_ = p.store.ClearPorts("ikuai")
	ports := make([]int, 0, len(mappings)*2)
	for _, m := range mappings {
		if !m.Enabled {
			continue
		}
		_ = p.store.UpsertPort(store.Port{
			ExternalPort: m.ExternalPort, InternalPort: m.InternalPort,
			InternalIP: m.InternalIP, Protocol: m.Protocol,
			Label: m.Comment, Enabled: true, Source: "ikuai",
		})
		ports = append(ports, m.ExternalPort, m.InternalPort)
	}
	// 同时纳入手工端口，避免同步后手工添加的端口脱离监控
	if all, err := p.store.ListPorts(true); err == nil {
		ports = ports[:0]
		for _, port := range all {
			ports = append(ports, port.ExternalPort, port.InternalPort)
		}
	}
	p.eng.SetPorts(ports)
	p.portsRefreshed.Add(1)
	p.log.Info("端口映射已同步", "count", len(mappings))
	return len(mappings), nil
}

// pollConns 拉取爱快连接表，喂给检测引擎。
func (p *Poller) pollConns() {
	if !p.cfg.ConnPollEnabled() {
		return
	}
	conns, err := p.client.Connections(p.cfg.ConnFuncName())
	if err != nil {
		p.log.Warn("拉取爱快连接表失败", "err", err)
		return
	}
	now := time.Now()
	for _, conn := range conns {
		p.eng.Feed(Observation{
			Kind: KindConn, IP: conn.SrcIP, Port: conn.DstPort,
			Proto: conn.Proto, Detail: "dst=" + conn.DstIP, TS: now,
		})
	}
	p.connsPolled.Add(uint64(len(conns)))
}

func (p *Poller) Stop() {
	if !p.running.CompareAndSwap(true, false) {
		return
	}
	if p.cancel != nil {
		p.cancel()
	}
	p.log.Info("爱快 API 轮询已停止")
}

func (p *Poller) Stats() map[string]any {
	return map[string]any{
		"running":         p.running.Load(),
		"ports_refreshed": p.portsRefreshed.Load(),
		"conns_polled":    p.connsPolled.Load(),
		"conn_diag":       p.client.ConnDiagnostic(),
	}
}

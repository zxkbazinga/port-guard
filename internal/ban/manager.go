// Package ban 管理封禁生命周期：收到告警 → 记录本地封禁 → 到期自动解封。
// 串联代理模式下封禁在代理的 accept 阶段生效，不再依赖爱快封禁 API。
package ban

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/detector"
	"github.com/zxkbazinga/port-guard/internal/store"
)

// Manager 负责执行与解除本地封禁。
type Manager struct {
	cfg    *config.Config
	log    *slog.Logger
	store  *store.Store
	mu     sync.Mutex
	cancel context.CancelFunc
	banned atomic.Uint64
}

func New(cfg *config.Config, log *slog.Logger, s *store.Store) *Manager {
	return &Manager{cfg: cfg, log: log, store: s}
}

func (m *Manager) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.cancel = cancel
	m.mu.Unlock()
	go m.expiryLoop(ctx)
}

// HandleAlert 处理检测引擎的告警：校验白名单 → 写本地封禁 → 记录事件。
func (m *Manager) HandleAlert(a detector.Alert) {
	if m.cfg.IsProtected(a.IP) {
		m.log.Debug("告警 IP 在保护名单中，跳过封禁", "ip", a.IP)
		return
	}
	if existing, _ := m.store.GetBan(a.IP); existing != nil && existing.Active && existing.ExpiresAt > time.Now().Unix() {
		m.log.Debug("IP 已在封禁中，跳过重复封禁", "ip", a.IP)
		return
	}
	minutes := m.cfg.BanMinutes()
	now := time.Now()
	_ = m.store.UpsertBan(store.Ban{
		IP: a.IP, Reason: a.Reason + " (" + a.Rule + ")",
		CreatedAt: now.Unix(), ExpiresAt: now.Add(time.Duration(minutes) * time.Minute).Unix(),
		Duration: minutes, Source: a.Rule, RuleID: "", Active: true,
	})
	_ = m.store.AddEvent(store.Event{
		Type: "attack", IP: a.IP, Port: a.Port, Protocol: a.Proto,
		Reason: a.Reason, Detail: a.Evidence,
		Action: "封禁 " + time.Duration(minutes).String() + " (本地代理)",
	})
	m.banned.Add(1)
}

// ManualBan 手工封禁 IP。
func (m *Manager) ManualBan(ip string, minutes int, reason string) error {
	if m.cfg.IsProtected(ip) {
		return &ProtectedError{IP: ip}
	}
	if minutes <= 0 {
		minutes = m.cfg.BanMinutes()
	}
	now := time.Now()
	if err := m.store.UpsertBan(store.Ban{
		IP: ip, Reason: reason, CreatedAt: now.Unix(),
		ExpiresAt: now.Add(time.Duration(minutes) * time.Minute).Unix(),
		Duration:  minutes, Source: "manual", RuleID: "", Active: true,
	}); err != nil {
		return err
	}
	return m.store.AddEvent(store.Event{Type: "manual_ban", IP: ip, Reason: reason,
		Action: "手工封禁 " + time.Duration(minutes).String()})
}

// Unban 手工解封 IP。
func (m *Manager) Unban(ip string) error {
	b, err := m.store.GetBan(ip)
	if err != nil {
		return err
	}
	if b == nil {
		return nil
	}
	if err := m.store.DeactivateBan(ip); err != nil {
		return err
	}
	return m.store.AddEvent(store.Event{Type: "unban", IP: ip, Reason: "手工解除封禁", Action: "解封"})
}

// expiryLoop 每 5 秒检查一次到期封禁并自动解除本地状态。
func (m *Manager) expiryLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bans, err := m.store.ListBans(true)
			if err != nil {
				continue
			}
			now := time.Now().Unix()
			for _, b := range bans {
				if b.ExpiresAt > now {
					continue
				}
				_ = m.store.DeactivateBan(b.IP)
				_ = m.store.AddEvent(store.Event{Type: "expire", IP: b.IP, Reason: "封禁到期自动解除", Action: "解封"})
				m.log.Info("封禁到期自动解除", "ip", b.IP)
			}
		}
	}
}

func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		m.cancel()
	}
}

func (m *Manager) Stats() map[string]any {
	return map[string]any{"banned_total": m.banned.Load()}
}

type ProtectedError struct{ IP string }

func (e *ProtectedError) Error() string { return "IP " + e.IP + " 在保护名单内，拒绝封禁" }

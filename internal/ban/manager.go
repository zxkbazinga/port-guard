// Package ban 管理封禁生命周期：收到告警 → 调用爱快封禁 → 到期自动解封。
package ban

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/detector"
	"github.com/zxkbazinga/port-guard/internal/ikuai"
	"github.com/zxkbazinga/port-guard/internal/store"
)

// Manager 负责执行与解除封禁。
type Manager struct {
	cfg    *config.Config
	log    *slog.Logger
	client *ikuai.Client
	store  *store.Store
	mu     sync.Mutex
	cancel context.CancelFunc
	banned atomic.Uint64
	failed atomic.Uint64
}

func New(cfg *config.Config, log *slog.Logger, client *ikuai.Client, s *store.Store) *Manager {
	return &Manager{cfg: cfg, log: log, client: client, store: s}
}

func (m *Manager) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.cancel = cancel
	m.mu.Unlock()
	go m.expiryLoop(ctx)
}

// HandleAlert 处理检测引擎的告警：校验白名单 → 调爱快封禁 → 记录事件。
func (m *Manager) HandleAlert(a detector.Alert) {
	if m.cfg.IsProtected(a.IP) {
		m.log.Debug("告警 IP 在保护名单中，跳过封禁", "ip", a.IP)
		return
	}
	if a.NoBan {
		_ = m.store.AddEvent(store.Event{
			Type: "attack", IP: a.IP, Port: a.Port, Protocol: a.Proto,
			Reason: a.Reason, Detail: a.Evidence, Action: "仅告警，未封禁",
		})
		return
	}
	if existing, _ := m.store.GetBan(a.IP); existing != nil && existing.Active && existing.ExpiresAt > time.Now().Unix() {
		m.log.Debug("IP 已在封禁中，跳过重复封禁", "ip", a.IP)
		return
	}
	minutes := a.Minutes
	if minutes <= 0 {
		minutes = m.cfg.BanMinutes()
	}
	ruleID, err := m.client.Ban(a.IP, minutes, a.Reason)
	if err != nil {
		m.failed.Add(1)
		m.log.Error("调用爱快封禁失败", "ip", a.IP, "err", err)
		_ = m.store.AddEvent(store.Event{
			Type: "ban_failed", IP: a.IP, Port: a.Port, Protocol: a.Proto,
			Reason: a.Reason, Detail: a.Evidence, Action: err.Error(),
		})
		return
	}
	now := time.Now()
	_ = m.store.UpsertBan(store.Ban{
		IP: a.IP, Reason: a.Reason + " (" + a.Rule + ")",
		CreatedAt: now.Unix(), ExpiresAt: now.Add(time.Duration(minutes) * time.Minute).Unix(),
		Duration: minutes, Source: a.Rule, RuleID: ruleID, Active: true,
	})
	_ = m.store.AddEvent(store.Event{
		Type: "attack", IP: a.IP, Port: a.Port, Protocol: a.Proto,
		Reason: a.Reason, Detail: a.Evidence,
		Action: "封禁 " + time.Duration(minutes).String() + " (" + m.client.Mode() + ")",
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
	ruleID, err := m.client.Ban(ip, minutes, reason)
	if err != nil {
		return err
	}
	now := time.Now()
	if err := m.store.UpsertBan(store.Ban{
		IP: ip, Reason: reason, CreatedAt: now.Unix(),
		ExpiresAt: now.Add(time.Duration(minutes) * time.Minute).Unix(),
		Duration:  minutes, Source: "manual", RuleID: ruleID, Active: true,
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
	if err := m.client.Unban(ip, b.RuleID); err != nil {
		return err
	}
	if err := m.store.DeactivateBan(ip); err != nil {
		return err
	}
	return m.store.AddEvent(store.Event{Type: "unban", IP: ip, Reason: "手工解除封禁", Action: "解封"})
}

// expiryLoop 每 5 秒检查一次到期封禁并自动解封（爱快黑名单本身也会按分钟自动失效，
// 这里主要负责同步本地状态；ACL 模式则必须主动删除规则）。
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
				if err := m.client.Unban(b.IP, b.RuleID); err != nil {
					m.log.Warn("自动解封失败", "ip", b.IP, "err", err)
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
	return map[string]any{"banned_total": m.banned.Load(), "failed_total": m.failed.Load()}
}

type ProtectedError struct{ IP string }

func (e *ProtectedError) Error() string { return "IP " + e.IP + " 在保护名单内，拒绝封禁" }

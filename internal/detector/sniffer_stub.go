//go:build !linux

package detector

import (
	"log/slog"

	"github.com/zxkbazinga/port-guard/internal/config"
)

// Sniffer 在非 Linux 平台上的空实现，保证本地开发可编译。
// 实际部署目标（爱快 Docker）是 Linux，使用 sniffer.go 的完整实现。
type Sniffer struct {
	cfg *config.Config
	log *slog.Logger
}

func NewSniffer(cfg *config.Config, log *slog.Logger, _ *Engine) *Sniffer {
	return &Sniffer{cfg: cfg, log: log}
}

func (s *Sniffer) Start() error {
	s.log.Info("抓包检测在非 Linux 平台不可用，已跳过（Syslog / API 轮询仍可用）")
	return nil
}

func (s *Sniffer) Stop()                 {}
func (s *Sniffer) Stats() map[string]any { return map[string]any{"running": false, "packets": 0} }

package detector

import (
	"bytes"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/zxkbazinga/port-guard/internal/config"
)

// SyslogReceiver 接收爱快推送的 syslog，提取攻击告警与连接信息。
type SyslogReceiver struct {
	cfg      *config.Config
	log      *slog.Logger
	eng      *Engine
	conn     *net.UDPConn
	running  atomic.Bool
	wg       sync.WaitGroup
	received atomic.Uint64
}

func NewSyslogReceiver(cfg *config.Config, log *slog.Logger, eng *Engine) *SyslogReceiver {
	return &SyslogReceiver{cfg: cfg, log: log, eng: eng}
}

func (s *SyslogReceiver) Start() error {
	if !s.cfg.SyslogEnabled() {
		return nil
	}
	addr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: s.cfg.SyslogPort()}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return err
	}
	s.conn = conn
	s.running.Store(true)
	s.log.Info("Syslog 接收已启动", "port", s.cfg.SyslogPort())

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		buf := make([]byte, 65535)
		for {
			n, _, err := conn.ReadFromUDP(buf)
			if err != nil {
				if s.running.Load() {
					s.log.Warn("Syslog 读取失败", "err", err)
				}
				return
			}
			s.received.Add(1)
			s.parse(string(bytes.TrimSpace(buf[:n])))
		}
	}()
	return nil
}

var (
	reIPv4      = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	reSRC       = regexp.MustCompile(`(?i)\b(?:SRC|src_ip|srcip|source|源ip)[=: ]+([0-9]{1,3}(?:\.[0-9]{1,3}){3})`)
	reDPT       = regexp.MustCompile(`(?i)\b(?:DPT|dst_port|dport|目的端口)[=: ]+(\d+)`)
	attackWords = []string{"扫描", "攻击", "flood", "syn flood", " udp flood", "阻断", "拦截", "drop", "blocked", "intrusion", "exploit"}
)

func (s *SyslogReceiver) parse(line string) {
	if line == "" {
		return
	}
	lower := strings.ToLower(line)
	isAttack := false
	for _, word := range attackWords {
		if strings.Contains(lower, word) {
			isAttack = true
			break
		}
	}
	if !isAttack {
		return
	}

	ipMatch := reSRC.FindStringSubmatch(line)
	if ipMatch == nil {
		ipMatch = reIPv4.FindStringSubmatch(line)
	}
	if ipMatch == nil {
		return
	}
	ip := ipMatch[1]
	port := 0
	if m := reDPT.FindStringSubmatch(line); m != nil {
		port, _ = strconv.Atoi(m[1])
	}
	s.eng.Feed(Observation{
		Kind: KindSyslog, IP: ip, Port: port, Proto: "",
		Detail: truncate(line, 200),
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func (s *SyslogReceiver) Stop() {
	if !s.running.CompareAndSwap(true, false) {
		return
	}
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.wg.Wait()
	s.log.Info("Syslog 接收已停止", "messages", s.received.Load())
}

func (s *SyslogReceiver) Stats() map[string]any {
	return map[string]any{"running": s.running.Load(), "messages": s.received.Load()}
}

//go:build linux

package detector

import (
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/sys/unix"

	"github.com/zxkbazinga/port-guard/internal/config"
)

// Sniffer 通过 Linux AF_PACKET 原始套接字抓包（纯 Go，不依赖 libpcap）。
// 若爱快 Docker 不支持抓包，启动失败只记录警告，不影响 Syslog / API 轮询。
type Sniffer struct {
	cfg     *config.Config
	log     *slog.Logger
	eng     *Engine
	running atomic.Bool
	fd      int
	packets atomic.Uint64
}

func htons(x uint16) uint16 { return (x << 8) | (x >> 8) }

func NewSniffer(cfg *config.Config, log *slog.Logger, eng *Engine) *Sniffer {
	return &Sniffer{cfg: cfg, log: log, eng: eng, fd: -1}
}

func (s *Sniffer) Start() error {
	if !s.cfg.SnifferEnabled() {
		s.log.Info("抓包检测已关闭（sniffer_enabled=false）")
		return nil
	}
	iface := s.cfg.SnifferIface()
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("创建 AF_PACKET socket 失败: %w", err)
	}
	index := 0 // 0 = 所有网卡
	if iface != "" && iface != "any" {
		ni, err := net.InterfaceByName(iface)
		if err != nil {
			unix.Close(fd)
			return fmt.Errorf("网卡 %s 不存在: %w", iface, err)
		}
		index = ni.Index
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: index}); err != nil {
		unix.Close(fd)
		return fmt.Errorf("绑定网卡失败: %w", err)
	}
	s.fd = fd
	s.running.Store(true)
	s.log.Info("抓包检测已启动", "iface", iface)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				if s.running.Load() {
					s.log.Warn("抓包读取失败", "err", err)
				}
				return
			}
			if !s.running.Load() {
				return
			}
			s.packets.Add(1)
			packet := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.Lazy)
			s.handlePacket(packet)
		}
	}()
	return nil
}

func (s *Sniffer) handlePacket(packet gopacket.Packet) {
	ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ok {
		return
	}
	srcIP := ipv4.SrcIP.String()
	ts := packet.Metadata().Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		// 只统计 SYN（三次握手第一步），排除服务端 SYN+ACK
		if tcp.SYN && !tcp.ACK {
			s.eng.Feed(Observation{Kind: KindSYN, IP: srcIP, Port: int(tcp.DstPort), Proto: "tcp", Detail: "SYN", TS: ts})
		}
		return
	}
	if udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		s.eng.Feed(Observation{Kind: KindUDP, IP: srcIP, Port: int(udp.DstPort), Proto: "udp", Detail: "UDP", TS: ts})
	}
}

func (s *Sniffer) Stop() {
	if !s.running.CompareAndSwap(true, false) {
		return
	}
	if s.fd >= 0 {
		_ = unix.Close(s.fd)
		s.fd = -1
	}
	s.log.Info("抓包检测已停止", "packets", s.packets.Load())
}

func (s *Sniffer) Stats() map[string]any {
	return map[string]any{"running": s.running.Load(), "packets": s.packets.Load()}
}

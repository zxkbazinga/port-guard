package main

import (
	"context"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zxkbazinga/port-guard/internal/ban"
	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/detector"
	"github.com/zxkbazinga/port-guard/internal/notify"
	"github.com/zxkbazinga/port-guard/internal/proxy"
	"github.com/zxkbazinga/port-guard/internal/store"
	"github.com/zxkbazinga/port-guard/internal/version"
	"github.com/zxkbazinga/port-guard/internal/web"
)

func main() {
	listen := flag.String("listen", ":5657", "Web 管理界面监听地址")
	dataDir := flag.String("data", "/data", "数据目录（SQLite 数据库）")
	logLevel := flag.String("log-level", "info", "日志级别：debug/info/warn/error")
	flag.Parse()

	level := slog.LevelInfo
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)
	logger.Info("Port Guard 启动", "version", version.Version)

	// 持久化层
	s, err := store.Open(*dataDir + "/port-guard.db")
	if err != nil {
		logger.Error("打开数据库失败", "err", err)
		os.Exit(1)
	}
	defer s.Close()

	cfg, err := config.New(s)
	if err != nil {
		logger.Error("加载配置失败", "err", err)
		os.Exit(1)
	}
	// 首次运行时把默认明文密码转换为 PBKDF2 哈希
	if cfg.WebPasswordHash() == "$2y$default$portguard" {
		if hash, err := hashDefaultPassword(); err == nil {
			_ = cfg.SetPassword(hash)
		}
	}
	// 一次性迁移：旧版本默认保存了 30 天日志保留，按新默认策略收敛为 3 天。
	if storedKeys, err := s.AllConfig(); err == nil {
		if _, done := storedKeys["log_retention_migrated"]; !done {
			if cfg.EventRetentionDays() > 3 {
				_ = cfg.Update(map[string]any{"event_retention_days": 3})
				logger.Info("日志保留天数已按默认策略调整为 3 天，可在系统配置中修改")
			}
			_ = s.SetConfigs(map[string]any{"log_retention_migrated": true})
		}
	}

	manager := ban.New(cfg, logger, s)
	// 钉钉通知：新封禁写入成功后异步推送，配置从 Web 保存即时生效。
	notifier := notify.New(cfg, logger)
	manager.SetNotifier(notifier)

	// 检测引擎：告警回调 → 代理本地封禁（accept 阶段即时生效）+ 封禁记录
	var proxyServer *proxy.Server
	engine := detector.New(cfg, logger, func(a detector.Alert) {
		if proxyServer != nil {
			proxyServer.Block(a.IP, 0)
		}
		go manager.HandleAlert(a)
	})
	proxyServer = proxy.New(cfg, logger, engine, s)
	notifier.SetCountryLookup(proxyServer.Country)

	// 地区拒绝也拉黑：与检测告警走同一条封禁链路（本地即时 + DB 记录，
	// 封禁管理页可见），但不喂检测引擎，避免污染连接频率等统计。
	proxyServer.SetGeoDenyHook(func(ip string, port int) {
		proxyServer.Block(ip, 0)
		go manager.HandleAlert(detector.Alert{
			IP: ip, Port: port, Proto: "tcp",
			Rule: "geo_block", Reason: "地区限制拒绝",
			Detail: "来源地区不在允许范围",
		})
	})

	syslogd := detector.NewSyslogReceiver(cfg, logger, engine)

	// 启动检测源；Syslog 接收 NAS / Windows 转发的安全日志
	if err := syslogd.Start(); err != nil {
		logger.Warn("Syslog 接收不可用", "err", err)
	}
	// 先恢复数据库中的未到期封禁，再启动监听：重启后新连接立即被拒绝，
	// 不必等该 IP 再次触发检测规则。
	proxyServer.RestoreBans()
	if err := proxyServer.Reload(); err != nil {
		logger.Warn("代理转发启动失败", "err", err)
	}
	manager.Start()
	notifier.Start()

	webServer, err := web.NewServer(web.Components{
		Cfg: cfg, Store: s, Engine: engine, Syslog: syslogd, Proxy: proxyServer,
		Bans: manager, Notifier: notifier, Log: logger,
	})
	if err != nil {
		logger.Error("初始化 Web 服务失败", "err", err)
		os.Exit(1)
	}

	httpServer := &http.Server{
		Addr: *listen, Handler: webServer.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		logger.Info("Web 管理界面已启动", "addr", *listen)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Web 服务异常退出", "err", err)
			os.Exit(1)
		}
	}()

	// 日志清理：启动时立即清理一次，之后每 6 小时执行
	prune := func() {
		days := cfg.EventRetentionDays()
		if days < 1 {
			return
		}
		if err := s.PruneEvents(days); err != nil {
			logger.Warn("清理事件日志失败", "err", err)
		}
		if err := s.PruneOldBans(days); err != nil {
			logger.Warn("清理封禁历史失败", "err", err)
		}
		logger.Info("日志清理完成", "retention_days", days)
	}
	prune()
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			prune()
		}
	}()

	// 优雅退出
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	logger.Info("正在关闭 Port Guard ...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(ctx)
	manager.Stop()
	notifier.Stop()
	syslogd.Stop()
	proxyServer.Stop()
	logger.Info("Port Guard 已退出")
}

func hashDefaultPassword() (string, error) {
	return web.HashPassword("portguard")
}

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
	"github.com/zxkbazinga/port-guard/internal/ikuai"
	"github.com/zxkbazinga/port-guard/internal/store"
	"github.com/zxkbazinga/port-guard/internal/version"
	"github.com/zxkbazinga/port-guard/internal/web"
)

func main() {
	listen := flag.String("listen", ":8080", "Web 管理界面监听地址")
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

	client := ikuai.New(cfg, logger)
	manager := ban.New(cfg, logger, client, s)

	// 检测引擎：告警回调 -> 封禁管理器
	engine := detector.New(cfg, logger, func(a detector.Alert) {
		go manager.HandleAlert(a)
	})

	// 从数据库加载端口集合
	ports, _ := s.ListPorts(true)
	values := make([]int, 0, len(ports)*2)
	for _, p := range ports {
		values = append(values, p.ExternalPort, p.InternalPort)
	}
	engine.SetPorts(values)

	sniffer := detector.NewSniffer(cfg, logger, engine)
	syslogd := detector.NewSyslogReceiver(cfg, logger, engine)
	poller := detector.NewPoller(cfg, logger, engine, client, s)

	// 启动各检测源；抓包在不支持的环境下失败只告警，不阻断启动
	if err := sniffer.Start(); err != nil {
		logger.Warn("抓包检测不可用", "err", err)
	}
	if err := syslogd.Start(); err != nil {
		logger.Warn("Syslog 接收不可用", "err", err)
	}
	poller.Start()
	manager.Start()

	webServer, err := web.NewServer(web.Components{
		Cfg: cfg, Store: s, Client: client, Engine: engine,
		Sniffer: sniffer, Syslog: syslogd, Poller: poller, Bans: manager, Log: logger,
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

	// 每天清理过期日志
	go func() {
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := s.PruneEvents(cfg.EventRetentionDays()); err != nil {
				logger.Warn("清理事件日志失败", "err", err)
			}
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
	poller.Stop()
	syslogd.Stop()
	sniffer.Stop()
	logger.Info("Port Guard 已退出")
}

func hashDefaultPassword() (string, error) {
	// 避免 main 包与 web 包循环依赖：直接复制最小哈希实现
	return web.HashPassword("portguard")
}

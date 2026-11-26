package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/detector"
	"github.com/zxkbazinga/port-guard/internal/store"
)

func testSetup(t *testing.T) (*config.Config, *store.Store, *detector.Engine, *slog.Logger) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	cfg, err := config.New(s)
	if err != nil {
		t.Fatal(err)
	}
	_ = cfg.Update(map[string]any{"proxy_enabled": true, "detection_enabled": false})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := detector.New(cfg, log, nil)
	return cfg, s, eng, log
}

// remoteAddrConn 用于测试：让 handle 认为连接来自指定公网 IP。
type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

// TestRecordRingBuffer 验证环形缓冲的顺序、上限、耗时回填与清空语义。
func TestRecordRingBuffer(t *testing.T) {
	cfg, s, eng, log := testSetup(t)
	p := New(cfg, log, eng, s)
	f := store.Forward{ListenPort: 22300}

	// 写满并超出容量，验证上限与顺序（最新在前）
	total := maxConnRecords + 5
	ids := make([]uint64, total)
	for i := 0; i < total; i++ {
		ids[i] = p.record(time.Now(), "1.2.3.4", f, "1.1.1.1:80", "转发", 0)
	}
	recs := p.Records(0)
	if len(recs) != maxConnRecords {
		t.Fatalf("记录数应为上限 %d，实际 %d", maxConnRecords, len(recs))
	}
	if recs[0].ID != ids[total-1] {
		t.Errorf("第一条应为最新记录 %d，实际 %d", ids[total-1], recs[0].ID)
	}
	if recs[len(recs)-1].ID != ids[5] {
		t.Errorf("最后一条应为第 6 条记录 %d，实际 %d", ids[5], recs[len(recs)-1].ID)
	}

	// 回填仍有效的记录耗时
	p.finishRecord(ids[total-1], 1500*time.Millisecond)
	if got := p.Records(1)[0].Duration; got != "1.5s" {
		t.Errorf("耗时回填失败，got %q", got)
	}
	// 已被覆盖的旧 ID 回填不应影响任何记录
	p.finishRecord(ids[0], time.Second)

	// limit 限制
	if got := len(p.Records(10)); got != 10 {
		t.Errorf("limit=10 应返回 10 条，实际 %d", got)
	}

	p.ClearRecords()
	if got := len(p.Records(0)); got != 0 {
		t.Errorf("清空后应为空，实际 %d", got)
	}
}

func TestGeoRestrictionRejectsForeignIP(t *testing.T) {
	cfg, s, eng, log := testSetup(t)
	if err := cfg.Update(map[string]any{"geo_mode": "cn"}); err != nil {
		t.Fatal(err)
	}
	p := New(cfg, log, eng, s)

	var hookIPs []string
	p.SetGeoDenyHook(func(ip string, _ int) { hookIPs = append(hookIPs, ip) })

	client, server := net.Pipe()
	defer client.Close()
	conn := &remoteAddrConn{Conn: server, remote: &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 55555}}
	p.handle(conn, store.Forward{ListenPort: 22300, BackendIP: "127.0.0.1", BackendPort: 1})

	records := p.Records(5)
	if len(records) == 0 || records[0].Action != "地区限制拒绝" {
		t.Fatalf("期望境外 IP 被地区规则拦截，实际记录：%+v", records)
	}
	if records[0].Country != "美国" {
		t.Fatalf("期望日志带归属地「美国」，实际 %q", records[0].Country)
	}
	// 地区拒绝应触发一次封禁回调；未注入回调的 IP 不应被误拉黑
	if len(hookIPs) != 1 || hookIPs[0] != "8.8.8.8" {
		t.Fatalf("期望触发一次地区封禁回调(8.8.8.8)，实际：%v", hookIPs)
	}
}

// TestGeoDenyBlockHook 验证地区拒绝回调确实写入本地封禁表，
// 且同一 IP 的后续连接不会重复触发回调（避免连接洪水下的重复查库/写库）。
func TestGeoDenyBlockHook(t *testing.T) {
	cfg, s, eng, log := testSetup(t)
	if err := cfg.Update(map[string]any{"geo_mode": "cn"}); err != nil {
		t.Fatal(err)
	}
	p := New(cfg, log, eng, s)
	calls := 0
	p.SetGeoDenyHook(func(ip string, _ int) {
		calls++
		p.Block(ip, 0)
	})

	f := store.Forward{ListenPort: 22300, BackendIP: "127.0.0.1", BackendPort: 1}
	for i := 0; i < 5; i++ {
		client, server := net.Pipe()
		conn := &remoteAddrConn{Conn: server, remote: &net.TCPAddr{IP: net.ParseIP("8.8.8.8"), Port: 55555}}
		p.handle(conn, f)
		client.Close()
	}
	if calls != 1 {
		t.Fatalf("期望同一 IP 只触发一次封禁回调，实际 %d 次", calls)
	}
	if !p.isLocallyBanned("8.8.8.8") {
		t.Fatal("地区拒绝回调后 IP 应进入本地封禁表")
	}
}

// TestShortConnDetectionEndToEnd 模拟公网 IP 反复建立"连上即断、零传输"的连接
// （爆破/批量探测特征），验证累计达到阈值后由引擎产生 short_conn 告警。
func TestShortConnDetectionEndToEnd(t *testing.T) {
	cfg, s, _, log := testSetup(t)
	if err := cfg.Update(map[string]any{
		"detection_enabled": true, "geo_mode": "off",
		"short_conn_threshold": 8, "alert_cooldown_seconds": 300,
	}); err != nil {
		t.Fatal(err)
	}
	var alerts []detector.Alert
	eng := detector.New(cfg, log, func(a detector.Alert) { alerts = append(alerts, a) })

	// 后端：接受后立即关闭，制造零传输短连接
	bl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bl.Close()
	backendPort := bl.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, e := bl.Accept()
			if e != nil {
				return
			}
			_ = c.Close()
		}
	}()

	p := New(cfg, log, eng, s)
	f := store.Forward{ListenPort: 22300, BackendIP: "127.0.0.1", BackendPort: backendPort}
	src := &net.TCPAddr{IP: net.ParseIP("223.5.5.5"), Port: 40000} // 中国大陆公网 IP，非白名单
	for i := 0; i < 8; i++ {
		client, server := net.Pipe()
		src.Port = 40000 + i
		conn := &remoteAddrConn{Conn: server, remote: src}
		_ = client.Close() // 客户端立刻断开 => 零传输短连接
		p.handle(conn, f)
	}

	if len(alerts) != 1 {
		t.Fatalf("期望 1 条短连接告警，实际 %d 条", len(alerts))
	}
	if alerts[0].Rule != "short_conn" {
		t.Fatalf("期望 short_conn，实际 %s", alerts[0].Rule)
	}
	if alerts[0].IP != "223.5.5.5" {
		t.Fatalf("IP 错误: %s", alerts[0].IP)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func TestForwardEcho(t *testing.T) {
	cfg, s, eng, log := testSetup(t)
	backendPort := freePort(t)
	listenPort := freePort(t)

	// 后端回声服务
	bl, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", backendPort))
	if err != nil {
		t.Fatal(err)
	}
	defer bl.Close()
	go func() {
		for {
			c, err := bl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 128)
				n, _ := c.Read(buf)
				c.Write(buf[:n])
			}()
		}
	}()

	_ = s.UpsertForward(store.Forward{
		ListenPort: listenPort, BackendIP: "127.0.0.1", BackendPort: backendPort,
		Protocol: "tcp", Enabled: true,
	})
	p := New(cfg, log, eng, s)
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "hello-proxy")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello-proxy" {
		t.Fatalf("回声不符: %q", string(buf[:n]))
	}
	st := p.Stats()
	if st["total"].(uint64) != 1 {
		t.Fatalf("期望 total=1，实际 %v", st["total"])
	}
}

func TestLocalBanLifecycle(t *testing.T) {
	cfg, s, eng, log := testSetup(t)
	p := New(cfg, log, eng, s)

	if p.isLocallyBanned("8.8.8.8") {
		t.Fatal("初始不应封禁")
	}
	p.Block("8.8.8.8", 5)
	if !p.isLocallyBanned("8.8.8.8") {
		t.Fatal("Block 后应封禁")
	}
	if p.isLocallyBanned("1.1.1.1") {
		t.Fatal("其他 IP 不应被封禁")
	}
	p.Unblock("8.8.8.8")
	if p.isLocallyBanned("8.8.8.8") {
		t.Fatal("Unblock 后应解封")
	}

	// 过期封禁自动失效
	p.mu.Lock()
	p.localBan["9.9.9.9"] = time.Now().Add(-time.Minute).Unix()
	p.mu.Unlock()
	if p.isLocallyBanned("9.9.9.9") {
		t.Fatal("过期封禁不应生效")
	}

	// 0 分钟使用全局封禁时长（默认 30 分钟），不应永久封禁
	p.Block("5.5.5.5", 0)
	if !p.isLocallyBanned("5.5.5.5") {
		t.Fatal("0 分钟应使用全局封禁时长，应生效")
	}
	p.mu.Lock()
	until := p.localBan["5.5.5.5"]
	p.mu.Unlock()
	if until > time.Now().Add(31*time.Minute).Unix() {
		t.Fatalf("0 分钟不应超过全局时长，实际到期 %d", until)
	}
}

func TestRecordCapAndClear(t *testing.T) {
	cfg, s, eng, log := testSetup(t)
	p := New(cfg, log, eng, s)
	backend := "127.0.0.1:22"
	f := store.Forward{ListenPort: 22300}
	start := time.Now()
	for i := 0; i < maxConnRecords+50; i++ {
		p.record(start, "8.8.8.8", f, backend, "转发", time.Millisecond)
	}
	if got := len(p.Records(0)); got != maxConnRecords {
		t.Fatalf("日志应保留 %d 条，实际 %d", maxConnRecords, got)
	}
	if got := len(p.Records(10)); got != 10 {
		t.Fatalf("limit=10 应返回 10 条，实际 %d", got)
	}
	p.ClearRecords()
	if got := len(p.Records(0)); got != 0 {
		t.Fatalf("清空后应为 0 条，实际 %d", got)
	}

	id := p.record(start, "1.1.1.1", f, backend, "转发", 0)
	rows := p.Records(1)
	if len(rows) != 1 || rows[0].Duration != "连接中" {
		t.Fatalf("连接建立时应立即显示「连接中」，实际 %+v", rows)
	}
	p.finishRecord(id, 1500*time.Millisecond)
	rows = p.Records(1)
	if len(rows) != 1 || rows[0].Duration != "1.5s" {
		t.Fatalf("连接结束后应回填耗时，实际 %+v", rows)
	}
}

func TestDisabledForwardNotListened(t *testing.T) {
	cfg, s, eng, log := testSetup(t)
	port := freePort(t)
	_ = s.UpsertForward(store.Forward{
		ListenPort: port, BackendIP: "127.0.0.1", BackendPort: 12345,
		Protocol: "tcp", Enabled: false,
	})
	p := New(cfg, log, eng, s)
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	st := p.Stats()
	if len(st["ports"].([]int)) != 0 {
		t.Fatalf("停用的规则不应监听，实际 %v", st["ports"])
	}
}

func writeTestCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "port-guard-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// writeMismatchedCert 生成一张自签证书，其 SAN 里的 IP 与后端实际监听地址不一致，
// 用于验证「忽略 SSL 证书」场景下代理确实跳过了证书校验。
func writeMismatchedCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "internal-self-signed"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("10.99.99.99")},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "backend-fullchain.pem")
	keyPath := filepath.Join(dir, "backend-privkey.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestBackendTLSIgnoreCert(t *testing.T) {
	cfg, s, eng, log := testSetup(t)
	backendPort := freePort(t)
	listenPort := freePort(t)

	// 后端 HTTPS 服务：自签证书，SAN 里的 IP 与实际监听地址 127.0.0.1 不一致
	certFile, keyFile := writeMismatchedCert(t, t.TempDir())
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	bl, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", backendPort))
	if err != nil {
		t.Fatal(err)
	}
	defer bl.Close()
	tlsLn := tls.NewListener(bl, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 128)
				n, _ := c.Read(buf)
				_, _ = c.Write(buf[:n])
			}()
		}
	}()

	// 入口用普通 TCP 透传，后端启用 TLS；没有后端域名/SNI 可填
	_ = s.UpsertForward(store.Forward{
		ListenPort: listenPort, BackendIP: "127.0.0.1", BackendPort: backendPort,
		Protocol: "tcp", Enabled: true, BackendTLS: true,
	})
	p := New(cfg, log, eng, s)
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "hello-backend-tls")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("后端 HTTPS 自签证书应被忽略，连接却失败: %v", err)
	}
	if string(buf[:n]) != "hello-backend-tls" {
		t.Fatalf("回声不符: %q", string(buf[:n]))
	}
}

func TestTLSListenerTermination(t *testing.T) {
	cfg, s, eng, log := testSetup(t)
	backendPort := freePort(t)
	listenPort := freePort(t)

	bl, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", backendPort))
	if err != nil {
		t.Fatal(err)
	}
	defer bl.Close()
	go func() {
		for {
			c, err := bl.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 128)
				n, _ := c.Read(buf)
				_, _ = c.Write(buf[:n])
			}()
		}
	}()

	certFile, keyFile := writeTestCert(t, t.TempDir())
	_ = cfg.Update(map[string]any{"tls_cert_file": certFile, "tls_key_file": keyFile})
	_ = s.UpsertForward(store.Forward{
		ListenPort: listenPort, BackendIP: "127.0.0.1", BackendPort: backendPort,
		Protocol: "tcp", Enabled: true, ListenTLS: true,
	})
	p := New(cfg, log, eng, s)
	if err := p.Reload(); err != nil {
		t.Fatal(err)
	}
	defer p.Stop()

	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "hello-tls")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "hello-tls" {
		t.Fatalf("TLS 终结回声不符: %q", string(buf[:n]))
	}
}

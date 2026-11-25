// Package certsync 定时从配置指定的内网地址拉取 TLS 证书与私钥，
// 校验后原子写入 port-guard 的证书路径，并触发监听器重新加载。
package certsync

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
)

const maxPEMBytes = 1 << 20 // 1 MiB，足够覆盖常规证书链与私钥

// Status 是证书同步的当前状态。
type Status struct {
	Enabled     bool     `json:"enabled"`
	LastAttempt int64    `json:"last_attempt"`
	LastSuccess int64    `json:"last_success"`
	LastChanged int64    `json:"last_changed"`
	LastError   string   `json:"last_error"`
	CertPath    string   `json:"cert_path"`
	KeyPath     string   `json:"key_path"`
	CertExists  bool     `json:"cert_exists"`
	KeyExists   bool     `json:"key_exists"`
	Ready       bool     `json:"ready"`
	Subject     string   `json:"subject,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	DNSNames    []string `json:"dns_names,omitempty"`
}

// Manager 管理后台定时同步任务。
type Manager struct {
	cfg      *config.Config
	log      *slog.Logger
	client   *http.Client
	onUpdate func()
	stop     chan struct{}
	wg       sync.WaitGroup
	runMu    sync.Mutex
	mu       sync.Mutex
	status   Status
	lastTry  time.Time
}

func New(cfg *config.Config, log *slog.Logger, onUpdate func()) *Manager {
	return &Manager{
		cfg: cfg, log: log, onUpdate: onUpdate, stop: make(chan struct{}),
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

func (m *Manager) Start() {
	enabled, _, _, _, _, _ := m.cfg.CertSyncSettings()
	m.mu.Lock()
	m.status.Enabled = enabled
	m.mu.Unlock()
	m.wg.Add(1)
	go m.loop()
	if enabled {
		go func() { _ = m.SyncNow() }()
	}
}

func (m *Manager) Stop() {
	select {
	case <-m.stop:
		return
	default:
		close(m.stop)
	}
	m.wg.Wait()
}

func (m *Manager) loop() {
	defer m.wg.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			enabled, _, _, _, _, interval := m.cfg.CertSyncSettings()
			if !enabled {
				m.mu.Lock()
				m.status.Enabled = false
				m.mu.Unlock()
				continue
			}
			m.mu.Lock()
			m.status.Enabled = true
			last := m.lastTry
			m.mu.Unlock()
			if last.IsZero() || time.Since(last) >= time.Duration(interval)*time.Second {
				_ = m.SyncNow()
			}
		case <-m.stop:
			return
		}
	}
}

func (m *Manager) Stats() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.status
	out.DNSNames = append([]string(nil), m.status.DNSNames...)
	return out
}

// SyncNow 立即执行一次拉取；可由 API 或定时任务调用。
func (m *Manager) SyncNow() error {
	m.runMu.Lock()
	defer m.runMu.Unlock()

	enabled, jsonURL, certURL, keyURL, token, interval := m.cfg.CertSyncSettings()
	m.mu.Lock()
	m.lastTry = time.Now()
	m.status.Enabled = enabled
	m.status.LastAttempt = m.lastTry.Unix()
	m.mu.Unlock()

	if !enabled {
		return fmt.Errorf("证书自动同步未启用")
	}
	if interval < 60 {
		interval = 3600
	}
	_ = interval // 间隔由调度循环使用，SyncNow 不做节流。

	var certPEM, keyPEM []byte
	var err error
	if strings.TrimSpace(jsonURL) != "" {
		certPEM, keyPEM, err = m.fetchJSON(jsonURL, token)
	} else {
		if certURL == "" || keyURL == "" {
			err = fmt.Errorf("请配置 JSON 地址，或同时配置证书与私钥地址")
		} else {
			certPEM, err = m.fetchPEM(certURL, token)
			if err == nil {
				keyPEM, err = m.fetchPEM(keyURL, token)
			}
		}
	}
	if err != nil {
		m.setError(err)
		return err
	}
	if err := m.apply(certPEM, keyPEM); err != nil {
		m.setError(err)
		return err
	}
	return nil
}

func (m *Manager) fetchJSON(rawURL, token string) ([]byte, []byte, error) {
	data, err := m.fetchRaw(rawURL, token)
	if err != nil {
		return nil, nil, err
	}
	var payload struct {
		CertPEM    string `json:"cert_pem"`
		KeyPEM     string `json:"key_pem"`
		Cert       string `json:"cert"`
		Key        string `json:"key"`
		Fullchain  string `json:"fullchain"`
		PrivateKey string `json:"private_key"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, nil, fmt.Errorf("解析证书 JSON 失败: %w", err)
	}
	cert := firstNonEmpty(payload.CertPEM, payload.Fullchain, payload.Cert)
	key := firstNonEmpty(payload.KeyPEM, payload.PrivateKey, payload.Key)
	if cert == "" || key == "" {
		return nil, nil, fmt.Errorf("证书 JSON 缺少 cert_pem / key_pem 字段")
	}
	return []byte(cert), []byte(key), nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func (m *Manager) fetchPEM(rawURL, token string) ([]byte, error) {
	data, err := m.fetchRaw(rawURL, token)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(data), "-----BEGIN") {
		return nil, fmt.Errorf("%s 返回的内容不是 PEM", rawURL)
	}
	return data, nil
}

func (m *Manager) fetchRaw(rawURL, token string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("拉取 %s 返回 HTTP %d", rawURL, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxPEMBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxPEMBytes {
		return nil, fmt.Errorf("证书内容超过 %d 字节上限", maxPEMBytes)
	}
	return []byte(strings.TrimSpace(string(data))), nil
}

func (m *Manager) apply(certPEM, keyPEM []byte) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return fmt.Errorf("证书与私钥不匹配或格式错误: %v", err)
	}
	certFile, keyFile := m.cfg.TLSFiles()
	if filepath.Clean(certFile) == filepath.Clean(keyFile) {
		return fmt.Errorf("证书与私钥路径不能相同")
	}

	changed := false
	if !sameFile(certFile, certPEM) {
		if err := writePEMAtomic(certFile, append(trimCopy(certPEM), '\n'), 0o644); err != nil {
			return fmt.Errorf("写入证书失败: %w", err)
		}
		changed = true
	}
	if !sameFile(keyFile, keyPEM) {
		if err := writePEMAtomic(keyFile, append(trimCopy(keyPEM), '\n'), 0o600); err != nil {
			return fmt.Errorf("写入私钥失败: %w", err)
		}
		changed = true
	}

	status := m.newStatus(certFile, keyFile, pair)
	status.LastSuccess = time.Now().Unix()
	status.LastError = ""
	if changed {
		status.LastChanged = status.LastSuccess
	}
	m.mu.Lock()
	prev := m.status
	status.Enabled = true
	status.LastAttempt = prev.LastAttempt
	m.status = status
	if !changed {
		m.status.LastChanged = prev.LastChanged
	}
	m.mu.Unlock()

	if changed && m.onUpdate != nil {
		m.onUpdate()
	}
	if changed {
		m.log.Info("证书已自动更新并重载监听器", "cert", certFile)
	}
	return nil
}

func (m *Manager) newStatus(certFile, keyFile string, pair tls.Certificate) Status {
	st := Status{CertPath: certFile, KeyPath: keyFile, Ready: true, CertExists: true, KeyExists: true}
	if leaf, err := x509.ParseCertificate(pair.Certificate[0]); err == nil {
		st.Subject = leaf.Subject.String()
		st.NotAfter = leaf.NotAfter.Format("2006-01-02 15:04:05")
		st.DNSNames = leaf.DNSNames
	}
	return st
}

func (m *Manager) setError(err error) {
	m.mu.Lock()
	m.status.LastError = err.Error()
	m.status.Enabled = true
	m.mu.Unlock()
	m.log.Warn("证书自动同步失败", "err", err)
}

func trimCopy(in []byte) []byte {
	return []byte(strings.TrimSpace(string(in)))
}

func sameFile(path string, content []byte) bool {
	existing, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(existing)) == strings.TrimSpace(string(content))
}

// writePEMAtomic 在同目录写入临时文件后原子替换，避免读到半成品。
func writePEMAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".pg-sync-cert-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

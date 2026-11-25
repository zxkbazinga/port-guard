package certsync

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zxkbazinga/port-guard/internal/config"
	"github.com/zxkbazinga/port-guard/internal/store"
)

func testCertPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sync.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"sync.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func TestSyncFromJSON(t *testing.T) {
	certPEM, keyPEM := testCertPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"cert_pem": certPEM, "key_pem": keyPEM})
	}))
	defer srv.Close()

	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg, err := config.New(s)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "certs", "fullchain.pem")
	keyPath := filepath.Join(dir, "certs", "privkey.pem")
	err = cfg.Update(map[string]any{
		"tls_cert_file": certPath, "tls_key_file": keyPath,
		"cert_sync_enabled": true, "cert_sync_url": srv.URL,
		"cert_sync_token": "test-token", "cert_sync_interval_seconds": 60,
	})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	m := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), func() { calls.Add(1) })
	if err := m.SyncNow(); err != nil {
		t.Fatal(err)
	}
	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotCert) != certPEM {
		t.Fatalf("证书内容不符: %q", string(gotCert))
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("私钥权限应为 0600，实际 %v", info.Mode().Perm())
	}
	if calls.Load() != 1 {
		t.Fatalf("新增证书应触发一次重载，实际 %d", calls.Load())
	}
	st := m.Stats()
	if !st.Ready || st.Subject != "CN=sync.example.com" || st.LastSuccess == 0 {
		t.Fatalf("同步状态不正确: %+v", st)
	}
}

func TestSyncRejectsMismatch(t *testing.T) {
	certPEM, _ := testCertPEM(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, certPEM)
	}))
	defer srv.Close()

	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "sync.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cfg, err := config.New(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Update(map[string]any{
		"tls_cert_file":      filepath.Join(dir, "certs", "fullchain.pem"),
		"tls_key_file":       filepath.Join(dir, "certs", "privkey.pem"),
		"cert_sync_enabled":  true,
		"cert_sync_cert_url": srv.URL, "cert_sync_key_url": srv.URL,
		"cert_sync_interval_seconds": 60,
	}); err != nil {
		t.Fatal(err)
	}
	m := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	if err := m.SyncNow(); err == nil {
		t.Fatal("非 PEM 私钥应返回错误")
	}
	if m.Stats().LastError == "" {
		t.Fatal("失败原因应写入状态")
	}
}

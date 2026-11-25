// Package store 提供 SQLite 持久化。使用 modernc.org/sqlite 纯 Go 驱动，无需 CGO。
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store 线程安全的数据库封装。
type Store struct {
	db *sql.DB
	mu sync.RWMutex
}

// Forward 是一条 TCP 转发规则（代理模式）：监听本机端口，转发到内网后端。
// ListenTLS 表示监听端用证书终结客户端 HTTPS；BackendTLS 表示到后端重新发起 TLS。
type Forward struct {
	ID          int64  `json:"id"`
	ListenPort  int    `json:"listen_port"`
	BackendIP   string `json:"backend_ip"`
	BackendPort int    `json:"backend_port"`
	Protocol    string `json:"protocol"`
	Label       string `json:"label"`
	Enabled     bool   `json:"enabled"`
	UpdatedAt   int64  `json:"updated_at"`
	ListenTLS   bool   `json:"listen_tls"`
	BackendTLS  bool   `json:"backend_tls"`
	BackendSNI  string `json:"backend_sni"`
}

// Event 是一条检测/封禁事件。
type Event struct {
	ID       int64  `json:"id"`
	TS       int64  `json:"ts"`
	Type     string `json:"type"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Reason   string `json:"reason"`
	Detail   string `json:"detail"`
	Action   string `json:"action"`
}

// Ban 是一条封禁记录。
type Ban struct {
	ID        int64  `json:"id"`
	IP        string `json:"ip"`
	Reason    string `json:"reason"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	Duration  int    `json:"duration"`
	Source    string `json:"source"`
	RuleID    string `json:"rule_id"`
	Active    bool   `json:"active"`
}

const schema = `
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    type TEXT NOT NULL,
    ip TEXT DEFAULT '',
    port INTEGER DEFAULT 0,
    protocol TEXT DEFAULT '',
    reason TEXT DEFAULT '',
    detail TEXT DEFAULT '',
    action TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS forwards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    listen_port INTEGER NOT NULL UNIQUE,
    backend_ip TEXT NOT NULL,
    backend_port INTEGER NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    label TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    updated_at INTEGER DEFAULT 0,
    listen_tls INTEGER DEFAULT 0,
    backend_tls INTEGER DEFAULT 0,
    backend_sni TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    reason TEXT DEFAULT '',
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    duration INTEGER DEFAULT 0,
    source TEXT DEFAULT '',
    rule_id TEXT DEFAULT '',
    active INTEGER DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_bans_active ON bans(active, expires_at);
`

// Open 打开（必要时创建）数据库并初始化表结构。
func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("创建数据目录失败: %w", err)
		}
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	if _, err = db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("初始化数据库失败: %w", err)
	}
	if err = migrateForwards(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("升级转发规则表失败: %w", err)
	}
	return &Store{db: db}, nil
}

// migrateForwards 为旧数据库补齐 TLS 终结相关字段，保留既有转发规则。
func migrateForwards(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(forwards)")
	if err != nil {
		return err
	}
	cols := map[string]bool{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		cols[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	migrations := []struct{ name, ddl string }{
		{"listen_tls", "ALTER TABLE forwards ADD COLUMN listen_tls INTEGER DEFAULT 0"},
		{"backend_tls", "ALTER TABLE forwards ADD COLUMN backend_tls INTEGER DEFAULT 0"},
		{"backend_sni", "ALTER TABLE forwards ADD COLUMN backend_sni TEXT DEFAULT ''"},
	}
	for _, m := range migrations {
		if cols[m.name] {
			continue
		}
		if _, err := db.Exec(m.ddl); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }

// ---------------------------------------------------------------- config --

// GetConfig 读取单个配置项，不存在时返回 ok=false。
func (s *Store) GetConfig(key string) (json.RawMessage, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var value string
	err := s.db.QueryRow("SELECT value FROM config WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return json.RawMessage(value), true, nil
}

// AllConfig 返回全部配置项。
func (s *Store) AllConfig() (map[string]json.RawMessage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query("SELECT key, value FROM config")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]json.RawMessage{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		out[key] = json.RawMessage(value)
	}
	return out, rows.Err()
}

// SetConfigs 批量写入配置项。
func (s *Store) SetConfigs(values map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare("INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for key, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if _, err := stmt.Exec(key, string(encoded)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ---------------------------------------------------------------- events --

func (s *Store) AddEvent(e Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.TS == 0 {
		e.TS = time.Now().Unix()
	}
	_, err := s.db.Exec(`INSERT INTO events(ts, type, ip, port, protocol, reason, detail, action)
VALUES(?, ?, ?, ?, ?, ?, ?, ?)`, e.TS, e.Type, e.IP, e.Port, e.Protocol, e.Reason, e.Detail, e.Action)
	return err
}

func (s *Store) ListEvents(limit, offset int, eventType string) ([]Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	query := "SELECT id, ts, type, ip, port, protocol, reason, detail, action FROM events"
	var args []any
	if eventType != "" {
		query += " WHERE type = ?"
		args = append(args, eventType)
	}
	query += " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.TS, &e.Type, &e.IP, &e.Port, &e.Protocol, &e.Reason, &e.Detail, &e.Action); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) EventCount(eventType string, since int64) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	query := "SELECT COUNT(*) FROM events WHERE 1=1"
	var args []any
	if eventType != "" {
		query += " AND type = ?"
		args = append(args, eventType)
	}
	if since > 0 {
		query += " AND ts >= ?"
		args = append(args, since)
	}
	var n int
	err := s.db.QueryRow(query, args...).Scan(&n)
	return n, err
}

func (s *Store) PruneEvents(days int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM events WHERE ts < ?", time.Now().Unix()-int64(days)*86400)
	return err
}

// PruneOldBans 清理已解除且到期超过 days 天的封禁历史，防止表无限增长。
func (s *Store) PruneOldBans(days int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Unix() - int64(days)*86400
	_, err := s.db.Exec("DELETE FROM bans WHERE active = 0 AND expires_at < ?", cutoff)
	return err
}

// ------------------------------------------------------------------ bans --

func (s *Store) GetBan(ip string) (*Ban, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var b Ban
	var active int
	err := s.db.QueryRow(`SELECT id, ip, reason, created_at, expires_at, duration, source, rule_id, active FROM bans WHERE ip = ?`, ip).
		Scan(&b.ID, &b.IP, &b.Reason, &b.CreatedAt, &b.ExpiresAt, &b.Duration, &b.Source, &b.RuleID, &active)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	b.Active = active == 1
	return &b, nil
}

func (s *Store) ListBans(activeOnly bool) ([]Ban, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	query := "SELECT id, ip, reason, created_at, expires_at, duration, source, rule_id, active FROM bans"
	if activeOnly {
		query += " WHERE active = 1"
	}
	query += " ORDER BY created_at DESC"
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Ban
	for rows.Next() {
		var b Ban
		var active int
		if err := rows.Scan(&b.ID, &b.IP, &b.Reason, &b.CreatedAt, &b.ExpiresAt, &b.Duration, &b.Source, &b.RuleID, &active); err != nil {
			return nil, err
		}
		b.Active = active == 1
		out = append(out, b)
	}
	return out, rows.Err()
}

func (s *Store) UpsertBan(b Ban) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := 0
	if b.Active {
		active = 1
	}
	_, err := s.db.Exec(`
INSERT INTO bans(ip, reason, created_at, expires_at, duration, source, rule_id, active)
VALUES(?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(ip) DO UPDATE SET
    reason = excluded.reason, created_at = excluded.created_at, expires_at = excluded.expires_at,
    duration = excluded.duration, source = excluded.source, rule_id = excluded.rule_id, active = excluded.active`,
		b.IP, b.Reason, b.CreatedAt, b.ExpiresAt, b.Duration, b.Source, b.RuleID, active)
	return err
}

func (s *Store) DeactivateBan(ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE bans SET active = 0 WHERE ip = ?", ip)
	return err
}

func (s *Store) ActiveBanCount() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM bans WHERE active = 1 AND expires_at > ?", time.Now().Unix()).Scan(&n)
	return n, err
}

// ------------------------------------------------------------- forwards --

func (s *Store) ListForwards(enabledOnly bool) ([]Forward, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	query := "SELECT id, listen_port, backend_ip, backend_port, protocol, label, enabled, updated_at, listen_tls, backend_tls, backend_sni FROM forwards"
	if enabledOnly {
		query += " WHERE enabled = 1"
	}
	query += " ORDER BY listen_port"
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Forward
	for rows.Next() {
		var f Forward
		var enabled, listenTLS, backendTLS int
		if err := rows.Scan(&f.ID, &f.ListenPort, &f.BackendIP, &f.BackendPort,
			&f.Protocol, &f.Label, &enabled, &f.UpdatedAt,
			&listenTLS, &backendTLS, &f.BackendSNI); err != nil {
			return nil, err
		}
		f.Enabled = enabled == 1
		f.ListenTLS = listenTLS == 1
		f.BackendTLS = backendTLS == 1
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) UpsertForward(f Forward) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	enabled := 0
	if f.Enabled {
		enabled = 1
	}
	listenTLS := 0
	if f.ListenTLS {
		listenTLS = 1
	}
	backendTLS := 0
	if f.BackendTLS {
		backendTLS = 1
	}
	_, err := s.db.Exec(`
INSERT INTO forwards(listen_port, backend_ip, backend_port, protocol, label, enabled, updated_at, listen_tls, backend_tls, backend_sni)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(listen_port) DO UPDATE SET
    backend_ip = excluded.backend_ip,
    backend_port = excluded.backend_port,
    protocol = excluded.protocol,
    label = excluded.label,
    enabled = excluded.enabled,
    updated_at = excluded.updated_at,
    listen_tls = excluded.listen_tls,
    backend_tls = excluded.backend_tls,
    backend_sni = excluded.backend_sni`,
		f.ListenPort, f.BackendIP, f.BackendPort, f.Protocol, f.Label, enabled, time.Now().Unix(),
		listenTLS, backendTLS, f.BackendSNI)
	return err
}

func (s *Store) DeleteForward(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM forwards WHERE id = ?", id)
	return err
}

func (s *Store) SetForwardEnabled(id int64, enabled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := 0
	if enabled {
		v = 1
	}
	_, err := s.db.Exec("UPDATE forwards SET enabled = ?, updated_at = ? WHERE id = ?", v, time.Now().Unix(), id)
	return err
}

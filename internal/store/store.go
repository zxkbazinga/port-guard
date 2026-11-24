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

// Port 是一条端口映射记录（来自爱快 API 或手工添加）。
type Port struct {
	ID           int64  `json:"id"`
	ExternalPort int    `json:"external_port"`
	InternalPort int    `json:"internal_port"`
	InternalIP   string `json:"internal_ip"`
	Protocol     string `json:"protocol"`
	Label        string `json:"label"`
	Enabled      bool   `json:"enabled"`
	Source       string `json:"source"`
	UpdatedAt    int64  `json:"updated_at"`
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
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    external_port INTEGER NOT NULL,
    internal_port INTEGER NOT NULL,
    internal_ip TEXT DEFAULT '',
    protocol TEXT DEFAULT 'tcp',
    label TEXT DEFAULT '',
    enabled INTEGER DEFAULT 1,
    source TEXT DEFAULT 'manual',
    updated_at INTEGER DEFAULT 0,
    UNIQUE(external_port, protocol)
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
	return &Store{db: db}, nil
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

// ----------------------------------------------------------------- ports --

func (s *Store) ListPorts(enabledOnly bool) ([]Port, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	query := "SELECT id, external_port, internal_port, internal_ip, protocol, label, enabled, source, updated_at FROM ports"
	if enabledOnly {
		query += " WHERE enabled = 1"
	}
	query += " ORDER BY external_port, protocol"
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Port
	for rows.Next() {
		var p Port
		var enabled int
		if err := rows.Scan(&p.ID, &p.ExternalPort, &p.InternalPort, &p.InternalIP, &p.Protocol,
			&p.Label, &enabled, &p.Source, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.Enabled = enabled == 1
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) UpsertPort(p Port) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	enabled := 0
	if p.Enabled {
		enabled = 1
	}
	_, err := s.db.Exec(`
INSERT INTO ports(external_port, internal_port, internal_ip, protocol, label, enabled, source, updated_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(external_port, protocol) DO UPDATE SET
    internal_port = excluded.internal_port,
    internal_ip = excluded.internal_ip,
    label = excluded.label,
    enabled = excluded.enabled,
    source = excluded.source,
    updated_at = excluded.updated_at`,
		p.ExternalPort, p.InternalPort, p.InternalIP, p.Protocol, p.Label, enabled, p.Source, time.Now().Unix())
	return err
}

func (s *Store) DeletePort(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM ports WHERE id = ?", id)
	return err
}

func (s *Store) ClearPorts(source string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if source == "" {
		_, err := s.db.Exec("DELETE FROM ports")
		return err
	}
	_, err := s.db.Exec("DELETE FROM ports WHERE source = ?", source)
	return err
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

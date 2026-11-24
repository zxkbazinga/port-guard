package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// 密码哈希：PBKDF2-HMAC-SHA256 + 随机盐，仅用标准库实现。
const pbkdf2Iterations = 60000

// HashPassword 生成密码哈希（供首次启动初始化默认密码使用）。
func HashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := pbkdf2([]byte(password), salt, pbkdf2Iterations, 32)
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s", pbkdf2Iterations, hex.EncodeToString(salt), hex.EncodeToString(key)), nil
}

func verifyPassword(password, stored string) bool {
	parts := splitFields(stored, '$')
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	var iter int
	if _, err := fmt.Sscanf(parts[1], "%d", &iter); err != nil || iter < 1 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got := pbkdf2([]byte(password), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// pbkdf2 实现（HMAC-SHA256）。
func pbkdf2(password, salt []byte, iter, keyLen int) []byte {
	h := func(p, s []byte) []byte {
		block := append(append([]byte{}, s...), 0, 0, 0, 1)
		mac := hmacSHA256(p, block)
		out := append([]byte{}, mac...)
		prev := mac
		for i := 1; i < iter; i++ {
			prev = hmacSHA256(p, prev)
			for j := range out {
				out[j] ^= prev[j]
			}
		}
		return out
	}
	out := h(password, salt)
	if len(out) > keyLen {
		return out[:keyLen]
	}
	return out
}

func hmacSHA256(key, data []byte) []byte {
	block := make([]byte, 64)
	copy(block, key)
	for i := range block {
		block[i] ^= 0x36
	}
	inner := sha256.Sum256(append(append([]byte{}, block...), data...))
	for i := range block {
		block[i] ^= 0x6a
	}
	outer := sha256.Sum256(append(append([]byte{}, block...), inner[:]...))
	return outer[:]
}

func splitFields(s string, sep byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// sessionStore 保存 Web 登录会话（进程内，重启失效）。
type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: map[string]time.Time{}}
}

func (s *sessionStore) create(ttl time.Duration) string {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	token := hex.EncodeToString(buf)
	s.mu.Lock()
	s.sessions[token] = time.Now().Add(ttl)
	s.mu.Unlock()
	return token
}

func (s *sessionStore) valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(s.sessions, token)
		return false
	}
	return true
}

func (s *sessionStore) remove(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

package proxy

import (
	"testing"
	"time"

	"github.com/zxkbazinga/port-guard/internal/store"
)

func TestRestoreBansFromStore(t *testing.T) {
	cfg, s, eng, log := testSetup(t)
	now := time.Now().Unix()

	if err := s.UpsertBan(store.Ban{IP: "1.2.3.4", Reason: "conn_rate", ExpiresAt: now + 600, Active: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertBan(store.Ban{IP: "5.6.7.8", ExpiresAt: now - 10, Active: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertBan(store.Ban{IP: "9.10.11.12", ExpiresAt: now + 600, Active: false}); err != nil {
		t.Fatal(err)
	}

	p := New(cfg, log, eng, s)
	// 模拟刚发生、尚未落库的封禁：恢复逻辑不能缩短或删掉它
	p.mu.Lock()
	p.localBan["1.2.3.4"] = now + 1200
	p.localBan["13.14.15.16"] = now + 300
	p.mu.Unlock()

	p.RestoreBans()

	if !p.isLocallyBanned("1.2.3.4") {
		t.Error("活跃封禁未恢复")
	}
	if p.isLocallyBanned("5.6.7.8") {
		t.Error("已到期封禁不应恢复")
	}
	if p.isLocallyBanned("9.10.11.12") {
		t.Error("已解封 IP 不应恢复")
	}
	if !p.isLocallyBanned("13.14.15.16") {
		t.Error("仅存在于内存的封禁被误删")
	}

	p.mu.Lock()
	until := p.localBan["1.2.3.4"]
	p.mu.Unlock()
	if until != now+1200 {
		t.Errorf("更长的到期时间被缩短：got %d, want %d", until, now+1200)
	}
}

// TestBanSurvivesRestart 模拟容器重启：旧实例把封禁写库，新实例重建后应立即拦截。
func TestBanSurvivesRestart(t *testing.T) {
	cfg, s, eng, log := testSetup(t)
	now := time.Now().Unix()
	if err := s.UpsertBan(store.Ban{IP: "66.228.62.150", Reason: "地区限制拒绝",
		ExpiresAt: now + 1800, Active: true}); err != nil {
		t.Fatal(err)
	}

	restarted := New(cfg, log, eng, s)
	if restarted.isLocallyBanned("66.228.62.150") {
		t.Fatal("恢复前不应有封禁")
	}
	restarted.RestoreBans()
	if !restarted.isLocallyBanned("66.228.62.150") {
		t.Fatal("重启后 DB 中的活跃封禁未恢复到即时拦截表")
	}

	// 手工解封后再次重启，不应复活
	if err := s.DeactivateBan("66.228.62.150"); err != nil {
		t.Fatal(err)
	}
	restarted.Unblock("66.228.62.150")
	again := New(cfg, log, eng, s)
	again.RestoreBans()
	if again.isLocallyBanned("66.228.62.150") {
		t.Fatal("已解封的 IP 不应在下次启动时复活")
	}
}

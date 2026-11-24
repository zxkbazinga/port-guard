// Port Guard 前端小工具：概览页 15 秒自动刷新状态卡片与事件。
(function () {
  'use strict';
  if (window.location.pathname !== '/') return;
  setInterval(async function () {
    try {
      const res = await fetch('/api/status', { credentials: 'same-origin' });
      if (!res.ok) return;
      const s = await res.json();
      const cards = document.querySelectorAll('.card .value');
      if (cards.length >= 4) {
        cards[0].textContent = s.attacks_24h;
        cards[1].textContent = s.active_bans;
        cards[2].textContent = s.monitored_ports;
        cards[3].textContent = s.ban_mode || '未探测';
      }
    } catch (e) { /* 静默失败，不影响页面 */ }
  }, 15000);
})();

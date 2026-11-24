// Port Guard 前端小工具：概览自动刷新 + 配置页爱快连接测试。
(function () {
  'use strict';
  var path = window.location.pathname;
  if (path === '/') setupDashboard();
  if (path === '/config') setupConfigTest();

  function setupDashboard() {
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
  }

  function setupConfigTest() {
    const btn = document.getElementById('ikuai-test-btn');
    const out = document.getElementById('ikuai-test-result');
    if (!btn || !out) return;
    btn.addEventListener('click', async function () {
      const original = btn.textContent;
      btn.disabled = true;
      btn.textContent = '测试中…';
      out.hidden = false;
      out.className = 'alert';
      out.textContent = '正在连接爱快，请稍候…';
      try {
        const form = btn.closest('form');
        const val = function (name) { return form.querySelector('[name="' + name + '"]'); };
        const payload = {
          ikuai_host: val('ikuai_host').value.trim(),
          ikuai_port: Number(val('ikuai_port').value) || 80,
          ikuai_ssl: val('ikuai_ssl').checked,
          ikuai_username: val('ikuai_username').value.trim(),
          ikuai_password: val('ikuai_password').value,
          ikuai_timeout: Number(val('ikuai_timeout').value) || 5
        };
        const res = await fetch('/api/config/test-ikuai', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify(payload)
        });
        let data = null;
        try { data = await res.json(); } catch (e) { /* 非 JSON 响应 */ }
        if (!res.ok || !data) {
          const msg = data && data.error ? data.error : ('HTTP ' + res.status);
          showResult(out, false, '请求失败', [{ name: '接口调用', ok: false, message: msg }], '');
          return;
        }
        showResult(out, data.ok, data.ok ? '连接成功' : '连接失败', data.steps || [], data.base_url || '');
      } catch (e) {
        showResult(out, false, '请求失败', [{ name: '网络错误', ok: false, message: String(e) }], '');
      } finally {
        btn.disabled = false;
        btn.textContent = original;
      }
    });
  }

  function showResult(el, ok, title, steps, baseURL) {
    el.className = 'alert ' + (ok ? 'success' : 'error');
    el.textContent = '';
    const head = document.createElement('div');
    const strong = document.createElement('strong');
    strong.textContent = title;
    head.appendChild(strong);
    if (baseURL) {
      const url = document.createElement('span');
      url.className = 'muted mono';
      url.textContent = ' ' + baseURL;
      head.appendChild(url);
    }
    el.appendChild(head);
    const list = document.createElement('div');
    list.className = 'test-steps';
    steps.forEach(function (s) {
      const row = document.createElement('div');
      row.className = 'test-step ' + (s.ok ? 'ok' : 'fail');
      row.textContent = (s.ok ? '✓ ' : '✗ ') + s.name + '：' + s.message;
      list.appendChild(row);
    });
    el.appendChild(list);
  }
})();

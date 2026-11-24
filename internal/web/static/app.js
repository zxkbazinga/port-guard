// Port Guard 前端小工具：概览自动刷新 + 配置页爱快连接测试。
(function () {
  'use strict';
  var path = window.location.pathname;
  if (path === '/') setupDashboard();
  if (path === '/config') { setupConfigTest(); setupSectionSaves(); }

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
        var title = data.ok ? '连接成功' : '连接失败';
        if (data.ok && data.saved) {
          title = '连接成功，配置已保存' + (data.synced_ports ? '，已同步 ' + data.synced_ports + ' 条端口映射' : '');
        }
        showResult(out, data.ok, title, data.steps || [], data.base_url || '');
      } catch (e) {
        showResult(out, false, '请求失败', [{ name: '网络错误', ok: false, message: String(e) }], '');
      } finally {
        btn.disabled = false;
        btn.textContent = original;
      }
    });
  }

  // 配置页：每个模块右上角独立保存，只提交该模块内的字段。
  function setupSectionSaves() {
    document.querySelectorAll('.section-save').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        const panel = btn.closest('.panel');
        const feedback = panel.querySelector('.save-feedback');
        const label = btn.getAttribute('data-label') || '配置';
        const payload = collectSection(panel);
        const original = btn.textContent;
        btn.disabled = true;
        btn.textContent = '保存中…';
        feedback.hidden = true;
        try {
          const res = await fetch('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify(payload)
          });
          let data = null;
          try { data = await res.json(); } catch (e) { /* 非 JSON 响应 */ }
          if (!res.ok || !data || !data.ok) {
            const msg = data && data.error ? data.error : ('HTTP ' + res.status);
            showFeedback(feedback, false, label + '保存失败：' + msg);
            return;
          }
          showFeedback(feedback, true, '✓ 已保存');
        } catch (e) {
          showFeedback(feedback, false, label + '保存失败：' + String(e));
        } finally {
          btn.disabled = false;
          btn.textContent = original;
        }
      });
    });
  }

  function collectSection(panel) {
    const payload = {};
    panel.querySelectorAll('[name]').forEach(function (el) {
      const name = el.name;
      if (!name) return;
      // 密码框留空表示沿用已保存值，不提交；非空交给后端哈希处理
      if (name === 'ikuai_password' || name === 'web_password') {
        if (el.value !== '') payload[name] = el.value;
        return;
      }
      if (el.type === 'checkbox') {
        payload[name] = el.checked; // 取消勾选也要显式提交 false
      } else if (el.type === 'number') {
        const n = Number(el.value);
        payload[name] = Number.isFinite(n) ? n : 0;
      } else {
        payload[name] = typeof el.value === 'string' ? el.value.trim() : el.value;
      }
    });
    return payload;
  }

  function showFeedback(el, ok, message) {
    el.hidden = false;
    el.className = 'save-feedback ' + (ok ? 'ok' : 'err');
    el.textContent = message;
    clearTimeout(el._hideTimer);
    if (ok) {
      el._hideTimer = setTimeout(function () { el.hidden = true; }, 3000);
    }
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

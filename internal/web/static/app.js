// Port Guard 前端小工具：概览自动刷新 + 配置页模块级保存。
(function () {
  'use strict';
  var path = window.location.pathname;
  if (path === '/') setupDashboard();
  if (path === '/config') setupSectionSaves();
  if (path === '/proxy') setupProxyLogs();

  function setupDashboard() {
    setInterval(async function () {
      try {
        const res = await fetch('/api/status', { credentials: 'same-origin' });
        if (!res.ok) return;
        const s = await res.json();
        const cards = document.querySelectorAll('.card .value');
        if (cards.length >= 4 && s.proxy) {
          cards[0].textContent = s.attacks_24h;
          cards[1].textContent = s.active_bans;
          cards[2].textContent = s.proxy.total || 0;
          cards[3].textContent = (s.proxy.ports || []).length;
        }
      } catch (e) { /* 静默失败，不影响页面 */ }
    }, 15000);
  }

  function setupProxyLogs() {
    var body = document.getElementById('fwdLogBody');
    if (!body) return;
    var pause = document.getElementById('fwdLogPause');
    var paused = false;
    if (pause) {
      pause.addEventListener('change', function () { paused = pause.checked; });
    }
    async function refresh() {
      if (paused) return;
      try {
        const res = await fetch('/api/forwards/logs?limit=1000', { credentials: 'same-origin' });
        if (!res.ok) return;
        const data = await res.json();
        const rows = Array.isArray(data.records) ? data.records : [];
        if (!body) return;
        body.replaceChildren();
        rows.forEach(function (r) {
          const tr = document.createElement('tr');
          [r.Time, r.IP, r.Listen, r.Backend, r.Action, r.Duration].forEach(function (v, i) {
            const td = document.createElement('td');
            td.textContent = v == null ? '' : String(v);
            if (i === 0) td.className = 'nowrap';
            if (i === 1 || i === 2 || i === 3) td.className = 'mono';
            tr.appendChild(td);
          });
          body.appendChild(tr);
        });
        const counter = document.getElementById('fwdLogCount');
        if (counter) {
          counter.textContent = rows.length + (rows.length >= 1000 ? ' 条（已达上限）' : ' 条');
        }
      } catch (e) { /* 静默失败，不影响规则管理 */ }
    }
    refresh();
    setInterval(refresh, 3000);
  }

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
      if (name === 'web_password') {
        if (el.value !== '') payload[name] = el.value;
        return;
      }
      if (el.type === 'checkbox') {
        payload[name] = el.checked;
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
})();

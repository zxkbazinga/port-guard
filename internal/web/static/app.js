// Port Guard 前端小工具：概览自动刷新 + 配置页模块级保存。
(function () {
  'use strict';
  var path = window.location.pathname;
  if (path === '/') setupDashboard();
  if (path === '/config') { setupSectionSaves(); setupCertUpload(); setupNotifyTest(); }
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
          // API 字段是 JSON tag 的小写形式
          [r.time, r.ip, r.country, r.listen, r.backend, r.action, r.duration].forEach(function (v, i) {
            const td = document.createElement('td');
            td.textContent = v == null ? '' : String(v);
            if (i === 0) td.className = 'nowrap';
            if (i === 1 || i === 3 || i === 4) td.className = 'mono';
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

  window.copyFwdLogs = async function () {
    const result = document.getElementById('fwdCopyResult');
    try {
      const res = await fetch('/api/forwards/logs?limit=1000', { credentials: 'same-origin' });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const data = await res.json();
      const rows = Array.isArray(data.records) ? data.records : [];
      const lines = ['时间\t来源IP\t归属地\t监听\t后端\t动作\t耗时'];
      rows.forEach(function (r) {
        lines.push([r.time, r.ip, r.country, r.listen, r.backend, r.action, r.duration]
          .map(function (v) { return v == null ? '' : String(v); }).join('\t'));
      });
      const text = lines.join('\n');
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        // HTTP 页面或非安全上下文下 Clipboard API 不可用，退回 textarea 方案
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        if (!ok) throw new Error('浏览器拒绝复制');
      }
      if (result) {
        result.className = 'save-feedback ok';
        result.textContent = '✓ 已复制 ' + rows.length + ' 条';
        setTimeout(function () { result.textContent = ''; }, 3000);
      }
    } catch (e) {
      if (result) {
        result.className = 'save-feedback err';
        result.textContent = '复制失败：' + String(e);
        setTimeout(function () { result.textContent = ''; }, 4000);
      }
    }
  };

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

  function setupCertUpload() {
    const btn = document.getElementById('certUploadBtn');
    const certInput = document.getElementById('certFileInput');
    const keyInput = document.getElementById('keyFileInput');
    const status = document.getElementById('certStatus');
    const result = document.getElementById('certUploadResult');
    const genTokenBtn = document.getElementById('genTokenBtn');
    const copyPushBtn = document.getElementById('copyPushBtn');
    const pushResult = document.getElementById('pushCopyResult');
    const pushCmd = document.getElementById('pushCommand');
    const tokenInput = document.querySelector('input[name="api_token"]');
    if (!btn || !certInput || !keyInput) return;

    if (genTokenBtn && tokenInput) {
      genTokenBtn.addEventListener('click', function () {
        const arr = new Uint8Array(24);
        (window.crypto || window.msCrypto).getRandomValues(arr);
        const token = Array.prototype.map.call(arr, function (b) {
          return ('0' + b.toString(16)).slice(-2);
        }).join('');
        tokenInput.value = token;
        tokenInput.type = 'text';
        if (pushCmd) {
          pushCmd.value = 'curl -fsS -X POST -H "Authorization: Bearer ' + token +
            '" -F "cert=@$certFile" -F "key=@$keyFile" http://PORT_GUARD_IP:5657/api/certs/push';
        }
        showFeedback(pushResult, true, '✓ 已生成，请点「保存」并刷新页面');
      });
    }

    if (copyPushBtn && pushCmd) {
      copyPushBtn.addEventListener('click', async function () {
        try {
          const text = pushCmd.value;
          if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
          } else {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            const ok = document.execCommand('copy');
            document.body.removeChild(ta);
            if (!ok) throw new Error('浏览器拒绝复制');
          }
          showFeedback(pushResult, true, '✓ 已复制命令');
        } catch (e) {
          showFeedback(pushResult, false, '复制失败：' + String(e));
        }
      });
    }

    refreshStatus();

    btn.addEventListener('click', async function () {
      if (!certInput.files || !certInput.files[0] || !keyInput.files || !keyInput.files[0]) {
        showFeedback(result, false, '请选择证书链和私钥文件');
        return;
      }
      const original = btn.textContent;
      btn.disabled = true;
      btn.textContent = '上传中…';
      try {
        const certPEM = await readFileText(certInput.files[0]);
        const keyPEM = await readFileText(keyInput.files[0]);
        const res = await fetch('/api/certs', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ cert_pem: certPEM, key_pem: keyPEM })
        });
        let data = null;
        try { data = await res.json(); } catch (e) { /* 非 JSON 响应 */ }
        if (!res.ok || !data || !data.ready) {
          const msg = data && data.error ? data.error : ('HTTP ' + res.status);
          showFeedback(result, false, '上传失败：' + msg);
          return;
        }
        showFeedback(result, true, '✓ 已上传并生效');
        applyStatus(data);
      } catch (e) {
        showFeedback(result, false, '上传失败：' + String(e));
      } finally {
        btn.disabled = false;
        btn.textContent = original;
      }
    });

    async function refreshStatus() {
      try {
        const res = await fetch('/api/certs/status', { credentials: 'same-origin' });
        if (!res.ok) return;
        applyStatus(await res.json());
      } catch (e) { /* 静默失败 */ }
    }

    function applyStatus(data) {
      if (!status || !data) return;
      var text;
      if (data.ready) {
        text = '✓ 证书已就绪：' + (data.subject || '已加载') +
          (data.not_after ? '，到期 ' + data.not_after : '') +
          '。路径：' + data.cert_path;
        status.style.color = '#15803d';
      } else if (data.cert_exists && data.key_exists) {
        text = '证书文件存在，但证书与私钥不匹配或格式错误。路径：' + data.cert_path;
        status.style.color = '#b91c1c';
      } else {
        text = '尚未上传证书。当前读取路径：' + data.cert_path + ' / ' + data.key_path;
        status.style.color = '';
      }
      status.textContent = text;
    }

    function readFileText(file) {
      return new Promise(function (resolve, reject) {
        const reader = new FileReader();
        reader.onload = function () { resolve(String(reader.result || '')); };
        reader.onerror = function () { reject(new Error('读取文件失败')); };
        reader.readAsText(file);
      });
    }
  }

  function setupNotifyTest() {
    const btn = document.getElementById('notifyTestBtn');
    const result = document.getElementById('notifyTestResult');
    if (!btn || !result) return;
    btn.addEventListener('click', async function () {
      const panel = btn.closest('.panel');
      const original = btn.textContent;
      btn.disabled = true;
      btn.textContent = '发送中…';
      try {
        // 先保存本面板，保证测试用的是刚填的 Webhook 和密钥
        let res = await fetch('/api/config', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify(collectSection(panel))
        });
        let data = await res.json().catch(function () { return null; });
        if (!res.ok || !data || !data.ok) throw new Error(data && data.error ? data.error : ('HTTP ' + res.status));
        res = await fetch('/api/notify/test', { method: 'POST', credentials: 'same-origin' });
        data = await res.json().catch(function () { return null; });
        if (!res.ok || !data || !data.ok) throw new Error(data && data.error ? data.error : ('HTTP ' + res.status));
        showFeedback(result, true, '✓ 测试消息已发送');
      } catch (e) {
        showFeedback(result, false, '测试失败：' + String(e));
      } finally {
        btn.disabled = false;
        btn.textContent = original;
      }
    });
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

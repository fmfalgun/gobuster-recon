(function () {
  function param(name) {
    return new URLSearchParams(window.location.search).get(name);
  }
  function setText(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val != null ? String(val) : '—';
  }
  function statusClass(code) {
    if (code >= 200 && code < 300) return 'status-2xx';
    if (code >= 300 && code < 400) return 'status-3xx';
    if (code >= 400 && code < 500) return 'status-4xx';
    return 'status-other';
  }
  function fmtSize(bytes) {
    if (!bytes) return '—';
    if (bytes >= 1024) return (bytes / 1024).toFixed(1) + 'kb';
    return bytes + 'b';
  }

  document.addEventListener('DOMContentLoaded', function () {
    var d = param('d');
    if (!d) { window.location.href = 'dir-board.html'; return; }

    fetch('data/targets/' + d + '.json')
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (data) {
        setText('target-url-display', data.url || d);
        var contribEl = document.getElementById('contributor-meta');
        if (contribEl && data.display_name) {
          contribEl.textContent = data.display_name + (data.display_loc ? ' · ' + data.display_loc : '');
        }

        // Stat badges
        setText('val-finding-count', data.finding_count || 0);
        setText('val-status-2xx',    data.status_2xx   || 0);
        setText('val-wordlist',      data.wordlist      || '—');
        setText('val-method',        data.method        || '—');

        var cntEl = document.getElementById('val-finding-count');
        if (cntEl && (data.finding_count || 0) > 10) cntEl.style.color = 'var(--amber)';

        setText('scanned-at', (data.scanned_at || '').slice(0, 10));

        // Exposure flags
        var flagsCont = document.getElementById('exposure-flags');
        if (flagsCont) {
          var FLAGS = [
            {key: 'has_admin',      label: 'Admin Panel',   level: 'high'},
            {key: 'has_login',      label: 'Login Page',    level: 'warn'},
            {key: 'has_phpmyadmin', label: 'phpMyAdmin',    level: 'high'},
            {key: 'has_git',        label: '.git Exposed',  level: 'high'},
            {key: 'has_env',        label: '.env Exposed',  level: 'high'},
            {key: 'has_backup',     label: 'Backup File',   level: 'warn'},
          ];
          var row = document.createElement('div');
          row.className = 'exposure-flags-row';
          FLAGS.forEach(function (f) {
            var exposed = !!data[f.key];
            var cls = exposed ? (f.level === 'high' ? 'flag-exposed' : 'flag-warn') : 'flag-safe';
            var item = document.createElement('div');
            item.className = 'exposure-flag';
            item.innerHTML =
              '<span class="flag-badge ' + cls + '">' + f.label + (exposed ? ' !' : ' ✓') + '</span>';
            row.appendChild(item);
          });
          flagsCont.appendChild(row);
        }

        // Findings table
        var cont = document.getElementById('findings-container');
        var findings = (data.findings || []).slice().sort(function (a, b) { return b.status - a.status; });
        if (cont) {
          if (!findings.length) {
            cont.innerHTML = '<span class="empty">No paths found' + (data.method === 'http_fallback' ? ' (HTTP fallback mode — install gobuster for full scan)' : '') + '.</span>';
          } else {
            var tbl = '<table class="findings-table"><thead class="findings-thead"><tr>' +
              '<th class="col-path">Path</th>' +
              '<th class="col-status">Status</th>' +
              '<th class="col-size">Size</th>' +
              '<th class="col-redirect">Redirect</th>' +
              '</tr></thead><tbody>';
            findings.forEach(function (f) {
              var sCls = statusClass(f.status);
              tbl += '<tr class="findings-row">' +
                '<td class="col-path">' + f.path + '</td>' +
                '<td class="col-status ' + sCls + '">' + f.status + '</td>' +
                '<td class="col-size">' + fmtSize(f.size) + '</td>' +
                '<td class="col-redirect">' + (f.redirect || '') + '</td>' +
                '</tr>';
            });
            tbl += '</tbody></table>';
            cont.innerHTML = tbl;
          }
        }
      })
      .catch(function (err) {
        var box = document.getElementById('error-box');
        var msg = document.getElementById('error-message');
        if (box) box.style.display = 'block';
        if (msg) msg.textContent = 'Failed to load "' + d + '": ' + err.message;
      });
  });
})();

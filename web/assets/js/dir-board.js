(function () {
  var DATA_URL = 'data/index.json';

  function flagBadge(label, exposed, level) {
    var cls = exposed ? (level === 'high' ? 'flag-exposed' : 'flag-warn') : 'flag-safe';
    return '<span class="flag-badge ' + cls + '">' + label + (exposed ? ' !' : ' ✓') + '</span>';
  }

  function methodBadge(method) {
    var cls  = (method || '') === 'gobuster' ? 'method-gobuster' : 'method-fallback';
    var text = (method || '') === 'gobuster' ? 'gobuster' : 'http';
    return '<span class="method-badge ' + cls + '">' + text + '</span>';
  }

  function renderCard(entry) {
    var card = document.createElement('div');
    card.className = 'target-card';
    card.setAttribute('data-d', entry.d);

    var cnt     = entry.finding_count || 0;
    var cntCls  = cnt > 10 ? 'high' : cnt === 0 ? 'zero' : '';
    var cntHtml = '<span class="finding-count ' + cntCls + '">' + cnt + ' paths</span>';

    card.innerHTML =
      '<div class="card-header-row">' +
        '<span class="card-url">' + (entry.url || entry.d) + '</span>' +
        '<span class="card-date">' + (entry.last_refreshed || entry.scanned_at || '').slice(0, 10) + '</span>' +
      '</div>' +
      '<div class="card-stats">' +
        cntHtml + '  ' +
        '<span class="card-stat">' + (entry.status_2xx || 0) + ' 2xx</span>' +
        '<span class="card-stat">' + (entry.status_3xx || 0) + ' 3xx</span>' +
        '<span class="card-stat">[' + (entry.mode || 'dir') + ']</span>' +
        '  ' + methodBadge(entry.method) + '  ' +
        flagBadge('admin',   !!entry.has_admin,      'high') + ' ' +
        flagBadge('login',   !!entry.has_login,       'warn') + ' ' +
        flagBadge('.git',    !!entry.has_git,         'high') + ' ' +
        flagBadge('.env',    !!entry.has_env,         'high') +
      '</div>' +
      '<div class="card-contributor">' +
        '<span class="card-name">' + (entry.display_name || '') + '</span>' +
        '<span>' + (entry.display_loc || '') + '</span>' +
      '</div>';

    card.addEventListener('click', function () {
      window.location.href = 'target.html?d=' + encodeURIComponent(entry.d);
    });
    return card;
  }

  function render(targets) {
    var list = document.getElementById('target-list');
    if (!list) return;
    list.innerHTML = '';
    if (!targets.length) { list.innerHTML = '<p class="empty">No results.</p>'; return; }
    targets.forEach(function (e) { list.appendChild(renderCard(e)); });
  }

  function applySearch(all) {
    var input = document.getElementById('search-input');
    if (!input) return;
    input.addEventListener('input', function () {
      var q = input.value.trim().toLowerCase();
      render(!q ? all : all.filter(function (e) {
        return (e.url || '').toLowerCase().includes(q) || (e.d || '').toLowerCase().includes(q);
      }));
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    fetch(DATA_URL)
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (data) {
        var targets = (data.targets || []).slice().sort(function (a, b) {
          return (b.finding_count || 0) - (a.finding_count || 0);
        });

        var statsEl = document.getElementById('dir-stats');
        if (statsEl) {
          var totalFindings = targets.reduce(function (s, e) { return s + (e.finding_count || 0); }, 0);
          var adminCount    = targets.filter(function (e) { return e.has_admin; }).length;
          statsEl.textContent = targets.length + ' target' + (targets.length !== 1 ? 's' : '') +
            ' · ' + totalFindings + ' total paths · ' + adminCount + ' admin panel' + (adminCount !== 1 ? 's' : '') + ' exposed';
        }

        render(targets);
        applySearch(targets);
      })
      .catch(function (err) {
        var list = document.getElementById('target-list');
        if (list) list.innerHTML = '<p class="empty">Failed to load: ' + err.message + '</p>';
      });
  });
})();

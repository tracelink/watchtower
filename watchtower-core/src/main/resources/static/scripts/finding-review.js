(function () {
  'use strict';
  if (window.wtFindingReviewInstalled) return;
  window.wtFindingReviewInstalled = true;
  function initialize() {
    document.querySelectorAll('[data-feedback-page]').forEach(function (root) {
      if (root.dataset.reviewReady) return;
      root.dataset.reviewReady = 'true';
      var selected = new Map([[root.dataset.findingKey, Number(root.dataset.version)]]);
      var versions = new Map(selected);
      var page = 0, historyPage = 0, generation = 0, historyGeneration = 0, searchTimer, saving = false;
      var status = root.querySelector('[data-review-status]');
      // Correctness and handling are radio choices (UAT walkthrough, 2026-10-15).
      function choice(selector) { var checked = root.querySelector(selector + ' input:checked'); return checked ? checked.value : ''; }
      function query() { return new URLSearchParams({scanType: root.dataset.scanType, scanId: root.dataset.scanId, findingKey: root.dataset.findingKey}); }
      async function request(url, options) {
        var response = await fetch(url, options);
        if (!response.ok) {
          if (response.status === 409) throw new Error('Another reviewer changed this feedback. Your input is preserved. Review the latest history and reload the page before saving again.');
          throw new Error('Review request failed (' + response.status + '). Your input is preserved; retry when the service is available.');
        }
        return response.json();
      }
      function selectionChanged() {
        var holder = root.querySelector('[data-feedback-selection]');
        holder.replaceChildren();
        selected.forEach(function (_, key) {
          var input = document.createElement('input'); input.type = 'checkbox'; input.checked = true; input.value = key;
          input.setAttribute('aria-label', 'Selected occurrence'); holder.appendChild(input);
        });
        holder.dispatchEvent(new Event('change', {bubbles: true}));
        root.querySelector('[data-review-selected-count]').textContent = selected.size + ' occurrence' + (selected.size === 1 ? '' : 's') + ' selected';
        root.querySelector('[data-review-save]').disabled = saving || selected.size === 0;
      }
      async function choices() {
        var mine = ++generation, params = query();
        params.set('page', page); params.set('search', root.querySelector('[data-review-search]').value);
        var info = root.querySelector('[data-review-page-status]'); info.textContent = 'Loading findings…';
        try {
          var result = await request('/finding-feedback/review/items?' + params);
          if (mine !== generation || !root.isConnected) return;
          var area = root.querySelector('[data-review-options]'); area.replaceChildren();
          result.content.forEach(function (item) {
            versions.set(item.key, Math.max(versions.get(item.key) || 0, item.version));
            var label = document.createElement('label'), checkbox = document.createElement('input');
            checkbox.type = 'checkbox'; checkbox.value = item.key; checkbox.checked = selected.has(item.key);
            label.appendChild(checkbox);
            label.appendChild(document.createTextNode(' ' + item.title + ' · ' + item.severity + ' · ' + item.file + (item.line > 0 ? ':' + item.line : '')));
            checkbox.addEventListener('change', function () {
              if (checkbox.checked && !selected.has(item.key) && selected.size >= 100) {
                checkbox.checked = false; status.textContent = 'Select at most 100 occurrences.'; return;
              }
              if (checkbox.checked) selected.set(item.key, versions.get(item.key)); else selected.delete(item.key);
              selectionChanged();
            });
            area.appendChild(label);
          });
          info.textContent = result.totalElements ? result.totalElements + ' matching occurrences · page ' + (page + 1) + ' of ' + result.totalPages : 'No matching occurrences. Your existing selection is unchanged.';
          root.querySelector('[data-review-previous]').disabled = page === 0;
          root.querySelector('[data-review-next]').disabled = page + 1 >= result.totalPages;
        } catch (error) { if (mine === generation && root.isConnected) info.textContent = error.message; }
      }
      async function history() {
        var mine = ++historyGeneration, params = query(); params.set('page', historyPage);
        var info = root.querySelector('[data-review-history-status]'); info.textContent = 'Loading history…';
        try {
          var result = await request('/finding-feedback/review/history?' + params);
          if (mine !== historyGeneration || !root.isConnected) return;
          var area = root.querySelector('[data-review-history]'); area.replaceChildren();
          var JUDGMENT = {TRUE_POSITIVE: ['check_circle', 'True positive'], FALSE_POSITIVE: ['cancel', 'False positive'], UNKNOWN: ['help', 'Unknown']};
          function el(tag, cls, text) { var node = document.createElement(tag); if (cls) node.className = cls; if (text != null) node.textContent = text; return node; }
          result.content.forEach(function (entry) {
            var judgment = JUDGMENT[entry.judgment] || ['help', String(entry.judgment)];
            var row = el('div', 'wt-review-history__row wt-review-history__row--' + String(entry.judgment).toLowerCase());
            var icon = el('span', 'material-icons', judgment[0]); icon.setAttribute('aria-hidden', 'true');
            var body = el('div', 'wt-review-history__body');
            var line = el('div', 'wt-review-history__line');
            line.appendChild(el('strong', null, judgment[1]));
            line.appendChild(el('span', 'wt-mini-chip', String(entry.disposition).replace(/_/g, ' ').toLowerCase()));
            line.appendChild(el('span', 'wt-muted', entry.reviewer + ' · ' + (window.WatchtowerTime ? window.WatchtowerTime.format(entry.changedAt) : new Date(entry.changedAt).toLocaleString(undefined, {timeZoneName: 'short'}))));
            body.appendChild(line);
            if (entry.explanation) body.appendChild(el('p', null, entry.explanation));
            row.appendChild(icon); row.appendChild(body); area.appendChild(row);
          });
          info.textContent = result.totalElements ? result.totalElements + ' saved decisions · page ' + (historyPage + 1) + ' of ' + result.totalPages : 'No reviews yet.';
          root.querySelector('[data-review-history-previous]').disabled = historyPage === 0;
          root.querySelector('[data-review-history-next]').disabled = historyPage + 1 >= result.totalPages;
        } catch (error) { if (mine === historyGeneration) info.textContent = error.message; }
      }
      root.querySelector('[data-review-form]').addEventListener('submit', async function (event) {
        event.preventDefault(); if (saving || !selected.size || selected.size > 100) return;
        saving = true; selectionChanged(); status.textContent = 'Saving feedback…';
        var headers = {'Content-Type': 'application/json'}; headers[root.dataset.csrfHeader] = root.dataset.csrfToken;
        var sent = new Map(selected);
        try {
          await request('/finding-feedback', {method: 'POST', headers: headers, body: JSON.stringify({
            scanType: root.dataset.scanType, scanId: Number(root.dataset.scanId), findingKeys: Array.from(sent.keys()),
            versions: Object.fromEntries(sent), judgment: choice('[data-review-judgment]'),
            disposition: choice('[data-review-disposition]'), explanation: root.querySelector('[data-review-explanation]').value
          })});
          sent.forEach(function (version, key) { versions.set(key, version + 1); if (selected.has(key)) selected.set(key, version + 1); });
          status.textContent = 'Feedback saved for ' + sent.size + ' occurrence' + (sent.size === 1 ? '' : 's') + '. Enforcement is unchanged.';
          document.dispatchEvent(new CustomEvent('wt:review-saved', {detail: {
            scanType: root.dataset.scanType, scanId: root.dataset.scanId,
            findingKeys: Array.from(sent.keys()), judgment: choice('[data-review-judgment]')
          }}));
        } catch (error) { status.textContent = error.message; }
        finally { saving = false; selectionChanged(); }
      });
      var bulk = root.querySelector('[data-review-bulk]');
      if (bulk) {
        bulk.addEventListener('toggle', function () { if (bulk.open) choices(); });
        root.querySelector('[data-review-search]').addEventListener('input', function () { clearTimeout(searchTimer); searchTimer = setTimeout(function () { page = 0; choices(); }, 200); });
        root.querySelector('[data-review-previous]').addEventListener('click', function () { if (page > 0) { page--; choices(); } });
        root.querySelector('[data-review-next]').addEventListener('click', function () { page++; choices(); });
      }
      var historySection = root.querySelector('[data-review-history-section]');
      historySection.addEventListener('toggle', function () { if (historySection.open && !historySection.dataset.loaded) { historySection.dataset.loaded = 'true'; historyPage = 0; history(); } });
      root.querySelector('[data-review-history-previous]').addEventListener('click', function () { if (historyPage > 0) { historyPage--; history(); } });
      root.querySelector('[data-review-history-next]').addEventListener('click', function () { historyPage++; history(); });
      selectionChanged();
    });
  }
  document.addEventListener('DOMContentLoaded', initialize);
  document.addEventListener('htmx:afterSwap', initialize);
  initialize();
})();

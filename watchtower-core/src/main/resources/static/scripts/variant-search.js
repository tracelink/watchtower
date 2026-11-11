(function () {
  'use strict';
  // R5.3 "Find similar code": three explained, deterministic steps. Results are places to review.
  var REPOSITORY_STATUS = {
    PENDING: 'Waiting', COMPLETE: 'Searched', PARTIAL: 'Searched, but the engine reported errors; results may be incomplete',
    UNSUPPORTED: 'Nothing here this rule can scan', FAILED: 'The rule could not run here', SKIPPED: 'Not searched'
  };
  var REASONS = {
    SOURCE_UNAVAILABLE: 'the code could not be downloaded (too large or unavailable)', BRANCH_UNAVAILABLE: 'the default branch was not found',
    REPOSITORY_UNAVAILABLE: 'the repository or its integration is unavailable', ENGINE_FAILED: 'the scanner engine failed',
    ACCESS_REVOKED: 'your access changed, so the search stopped', ENGINE_UNAVAILABLE: "this rule's engine was turned off",
    QUEUE_UNAVAILABLE: 'the search could not be queued', SEARCH_FAILED: 'the search stopped unexpectedly'
  };
  var state = {caseId: null, selected: new Map(), timer: null, queryTimer: null};
  function dialog() { return document.querySelector('[data-variant-dialog]'); }
  function el(name) { return dialog().querySelector('[data-variant-' + name + ']'); }
  function text(parent, tag, value) { var node = document.createElement(tag); node.textContent = value; parent.appendChild(node); return node; }
  function status(value) { el('status').textContent = value; }
  async function api(path, data) {
    var options = {headers: {'Content-Type': 'application/json'}};
    if (data !== undefined) {
      options.method = 'POST'; options.body = JSON.stringify(data);
      options.headers[dialog().dataset.csrfHeader] = dialog().dataset.csrfToken;
    }
    var response = await fetch(path, options), body = {};
    try { body = await response.json(); } catch (e) { body = {}; }
    if (!response.ok) throw new Error(body.error || 'Request unavailable (' + response.status + ').');
    return body;
  }
  function short(commit) { return commit ? commit.slice(0, 10) : 'not pinned yet'; }

  function proposal(p) {
    var area = el('proposal'); area.replaceChildren();
    text(area, 'p', p.explanation);
    if (!p.fixtures) return;
    if (p.status === 'READY') text(area, 'p', p.recorded_line_changed ? 'The recorded line ' + p.line + ' is part of the fix.' :
      'The recorded line ' + p.line + ' is not inside the changed lines; check the line on the case.');
    var code = text(area, 'pre', ''); code.className = 'wt-variant-excerpt';
    p.excerpt.forEach(function (line) {
      var row = text(code, 'span', String(line.line).padStart(5, ' ') + (line.changed ? ' − ' : '   ') + line.text + '\n');
      if (line.changed) row.className = 'is-changed';
    });
    var list = text(area, 'ul', '');
    p.fixtures.forEach(function (f) {
      text(list, 'li', (f.expected === 'MATCH' ? 'Must be flagged: ' : 'Must stay clean: ') + f.reference + ' (from commit ' + short(f.commit) + ', SHA-256 ' + f.sha256.slice(0, 12) + '…)');
    });
  }
  function selected() {
    el('selected').textContent = state.selected.size ? state.selected.size + ' of 25 repositories chosen: ' + Array.from(state.selected.values()).join(', ') : 'Choose up to 25 repositories.';
  }
  async function repositories() {
    var rows = await api('/repository/evidence/variants/repositories?q=' + encodeURIComponent(el('query').value || ''));
    var area = el('repositories'); area.replaceChildren();
    if (!rows.length) { text(area, 'p', 'No matching code repositories with a live integration.'); return; }
    rows.forEach(function (r) {
      var label = text(area, 'label', ''); label.className = 'wt-variant-repo';
      var box = document.createElement('input'); box.type = 'checkbox'; box.value = r.id; box.checked = state.selected.has(r.id);
      box.addEventListener('change', function () {
        if (box.checked && state.selected.size >= 25) { box.checked = false; status('A search can cover at most 25 repositories.'); return; }
        if (box.checked) state.selected.set(r.id, r.name); else state.selected.delete(r.id);
        selected();
      });
      label.appendChild(box); text(label, 'span', ' ' + r.name + ' (' + r.default_branch + ')');
    });
  }
  function search(view) {
    var box = text(el('searches'), 'section', ''); box.className = 'wt-variant-result';
    var running = view.status === 'QUEUED' || view.status === 'RUNNING';
    text(box, 'p', (running ? 'Searching… ' : view.status === 'DONE' ? 'Finished. ' : 'Stopped. ') + view.total_matches + ' places to review · rule ' + view.rule_id +
      (view.candidate_id ? ' draft ' + view.candidate_id : ' as it is now') + ' · started by ' + view.requested_by);
    var list = text(box, 'ul', '');
    (view.repositories || []).forEach(function (r) {
      var searched = r.status === 'COMPLETE' || r.status === 'PARTIAL';
      var item = text(list, 'li', r.repository + ' @ ' + short(r.commit) + ': ' + (REPOSITORY_STATUS[r.status] || r.status) +
        (r.error ? ' because ' + (REASONS[r.error] || r.error) : '') +
        (searched ? ' · ' + r.matches + (r.matches === 1 ? ' match' : ' matches') + (r.truncated ? ' (first 200 shown)' : '') : ''));
      if (r.locations && r.locations.length) {
        var places = text(item, 'ul', '');
        r.locations.forEach(function (l) { text(places, 'li', l.path + ':' + l.line); });
      }
    });
    return running;
  }
  async function searches() {
    clearTimeout(state.timer);
    var list = await api('/repository/evidence/variants/case/' + encodeURIComponent(state.caseId));
    el('searches').replaceChildren();
    var running = false;
    for (var summary of list.slice(0, 5)) running = search(await api('/repository/evidence/variants/' + encodeURIComponent(summary.id))) || running;
    if (running && dialog().open) state.timer = setTimeout(function () { searches().catch(function (e) { status(e.message); }); }, 5000);
  }
  async function open(button) {
    state.caseId = button.dataset.variantOpen; state.selected = new Map();
    el('case').textContent = 'Recorded miss: ' + button.dataset.caseSummary + '.';
    el('rule').value = button.dataset.ruleId || ''; el('candidate').value = ''; el('query').value = '';
    dialog().dataset.caseId = state.caseId;
    var drafted = dialog().querySelector('[data-ai-fixture-result]'); if (drafted) drafted.replaceChildren();
    el('proposal').replaceChildren(); el('searches').replaceChildren(); status(''); selected();
    await dialog().show();
    await repositories(); await searches();
  }
  document.addEventListener('click', async function (event) {
    var d = dialog(); if (!d) return;
    try {
      var opener = event.target.closest('[data-variant-open]');
      if (opener) { await open(opener); return; }
      if (!d.contains(event.target)) return;
      if (event.target.closest('[data-variant-close]')) { clearTimeout(state.timer); d.close(); return; }
      if (event.target.closest('[data-variant-compare]')) {
        status('Comparing commits…');
        proposal(await api('/repository/evidence/missed/case/' + encodeURIComponent(state.caseId) + '/proposal')); status('');
      }
      if (event.target.closest('[data-variant-save-tests]')) {
        var rule = Number(el('rule').value);
        if (!rule) { status('Enter the rule these tests belong to.'); return; }
        var saved = await api('/repository/evidence/missed/case/' + encodeURIComponent(state.caseId) + '/fixtures', {ruleId: rule});
        status(saved.fixtures.length + ' regression tests saved for rule ' + rule + '. Copy the files listed in step 1 into the reviewed fixture folder so the tests can run.');
      }
      if (event.target.closest('[data-variant-start]')) {
        if (!state.selected.size) { status('Choose at least one repository.'); return; }
        await api('/repository/evidence/variants', {caseId: state.caseId, ruleId: Number(el('rule').value) || null,
          candidateId: el('candidate').value.trim() || null, repositoryIds: Array.from(state.selected.keys())});
        status('Search started. It runs in the background; results appear below.');
        await searches();
      }
    } catch (error) { status(error.message); }
  });
  document.addEventListener('input', function (event) {
    if (!dialog() || !event.target.closest('[data-variant-query]')) return;
    clearTimeout(state.queryTimer);
    state.queryTimer = setTimeout(function () { repositories().catch(function (e) { status(e.message); }); }, 300);
  });
})();

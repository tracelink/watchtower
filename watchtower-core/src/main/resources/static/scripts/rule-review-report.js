(function () {
  'use strict';
  if (window.wtRuleReportsInstalled) return; window.wtRuleReportsInstalled = true;
  // Report only (plan R5.1): this dialog never changes enforcement or opens review items.
  var REASONS = {CONFIRMED_NOISE: 'Confirmed noise', REVIEW_OVERDUE: 'Review overdue', NO_OWNER: 'No owner',
    NO_RECENT_MATCHES: 'No recent matches', NO_CWE: 'No CWE'};
  var SOURCES = {finding_feedback: 'False-positive judgments', bypass: 'PR bypasses', review_outcome: 'Review decisions'};
  var latest = null;
  function dialog() { return document.querySelector('[data-rule-report-dialog]'); }
  function element(name) { return dialog().querySelector('[data-rule-report-' + name + ']'); }
  function text(parent, tag, value) { var el = document.createElement(tag); el.textContent = value; parent.appendChild(el); return el; }
  function status(value) { element('status').textContent = value; }
  function chip(parent, label, icon, tone, tip) {
    var el = document.createElement('span');
    el.className = 'wt-mini-chip' + (tone ? ' wt-mini-chip--' + tone : '');
    if (tip) { el.tabIndex = 0; el.setAttribute('data-tip', tip); }
    if (icon) { var i = text(el, 'span', icon); i.className = 'material-icons'; i.setAttribute('aria-hidden', 'true'); }
    text(el, 'span', label);
    parent.appendChild(el);
    return el;
  }
  // An empty tab is a picture, an icon and one line (UAT walkthrough, 2026-10-16).
  function empty(area, icon, title, hint) {
    var box = text(area, 'div', '');
    box.className = 'wt-empty-picture';
    var i = text(box, 'span', icon); i.className = 'material-icons wt-empty-picture__icon'; i.setAttribute('aria-hidden', 'true');
    text(box, 'strong', title);
    text(box, 'span', hint).className = 'wt-muted';
    return box;
  }
  var WEEKDAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
  function scheduleLabel(settings) { return settings.enabled ? 'Weekly · ' + (WEEKDAYS[settings.weekday - 1] || 'Monday') + ' (UTC)' : 'Schedule off'; }
  var CHECKS = {QUEUED: 'tests running', PASSED: 'reviewed tests still pass', FAILED: 'a reviewed test no longer matches its label',
    INCOMPLETE: 'some reviewed tests could not run', NO_TESTS: 'no reviewed tests for the changed rules', NOT_NEEDED: 'no rules changed', UNAVAILABLE: 'tests could not be queued'};
  async function call(url, data) {
    var options = {headers: {'Content-Type': 'application/json'}};
    if (data !== undefined) { options.method = 'POST'; options.body = JSON.stringify(data); options.headers[dialog().dataset.csrfHeader] = dialog().dataset.csrfToken; }
    var response = await fetch(url, options), body = {};
    try { body = await response.json(); } catch (e) { body = {}; }
    if (!response.ok) throw new Error(body.error || 'Upstream updates unavailable (' + response.status + ').');
    return body;
  }
  // R5.4: new provided rules from an upgrade report findings but do not block until approved here.
  function upstream(updates) {
    var area = element('upstream');
    if (!area) return; // no saved report yet: the summary tab is not on the page
    area.replaceChildren();
    if (!updates.length) { chip(area, 'No upstream rule changes since the baseline', 'check_circle', 'ok', 'No scanner rule catalog changes since the baseline.'); return; }
    var list = text(area, 'ul', '');
    list.className = 'wt-rule-report-list';
    updates.forEach(function (u) {
      var row = text(list, 'li', u.module + ' · ' + (window.WatchtowerTime ? window.WatchtowerTime.format(u.created_at) : new Date(u.created_at).toLocaleString(undefined, {timeZoneName: 'short'})) + ' · ' + u.added.length + ' new, ' +
        u.changed.length + ' changed, ' + u.removed.length + ' removed · ' + (CHECKS[u.check_status] || u.check_status));
      if (u.added.length) {
        var chip = text(row, 'span', u.approved_at ? 'Approved by ' + u.approved_by : u.held + ' new rules not blocking yet');
        chip.className = 'wt-status-chip';
        text(row, 'p', 'New: ' + u.added.map(function (a) { return a.name; }).join(', '));
      }
      if (u.removed.length) text(row, 'p', 'Removed (retired): ' + u.removed.join(', '));
      (u.check || []).filter(function (c) { return c.status === 'FAILED_EXPECTATION'; }).forEach(function (c) { text(row, 'p', 'Check rule ' + c.name + ': its reviewed tests no longer pass.'); });
      if (!u.approved_at && u.added.length && dialog().dataset.canModify === 'true') {
        var approve = document.createElement('md-outlined-button');
        approve.textContent = 'Let new rules block';
        approve.dataset.ruleReportApprove = u.id; approve.dataset.version = u.version;
        row.appendChild(approve);
      }
    });
  }
  async function api(path, data) {
    var options = {headers: {'Content-Type': 'application/json'}};
    if (data !== undefined) {
      options.method = 'POST';
      options.headers[dialog().dataset.csrfHeader] = dialog().dataset.csrfToken;
      options.body = JSON.stringify(data);
    }
    var response = await fetch('/rule/review-report' + path, options);
    var body = {};
    try { body = await response.json(); } catch (e) { body = {}; }
    if (!response.ok) throw new Error(body.error || 'Review report unavailable (' + response.status + ').');
    return body;
  }
  function detail(reason) {
    if (reason.code === 'CONFIRMED_NOISE') return reason.false_positives + ' of ' + reason.reviewed_sample + ' reviewed findings were false positives (90 days).';
    if (reason.code === 'REVIEW_OVERDUE') return 'Review was due ' + reason.review_by + '.';
    if (reason.code === 'NO_RECENT_MATCHES') return reason.note || '';
    return '';
  }
  function attention(summary) {
    var area = element('attention');
    area.replaceChildren();
    var items = (summary && summary.attention) || [];
    if (!items.length) { text(area, 'p', 'No rules need attention.'); return; }
    var list = text(area, 'ul', '');
    list.className = 'wt-rule-report-list';
    items.forEach(function (item) {
      var row = text(list, 'li', '');
      var link = document.createElement('a');
      link.textContent = item.name;
      link.href = '/rule/edit/' + encodeURIComponent(String(item.module).toLowerCase()) + '/' + encodeURIComponent(item.rule_id);
      row.appendChild(link);
      text(row, 'span', ' · ' + item.module + (item.owner ? ' · ' + item.owner : ''));
      item.reasons.forEach(function (reason) {
        var chip = text(row, 'span', REASONS[reason.code] || reason.code);
        chip.className = 'wt-status-chip';
        chip.title = detail(reason);
      });
      if (item.open_reviews) text(row, 'span', ' · ' + item.open_reviews + ' open review' + (item.open_reviews === 1 ? '' : 's'));
    });
    if (summary.attention_truncated) text(area, 'p', 'Showing the first ' + items.length + ' rules.');
  }
  function themes(summary) {
    var area = element('themes');
    if (!area) return; // no saved report yet
    area.replaceChildren();
    var items = (summary && summary.themes) || [];
    if (!summary) return;
    if (!items.length) { empty(area, 'category', 'No feedback themes in this report', 'Themes group similar finding feedback from the last 90 days. This report had none.'); return; }
    naming(area, summary.ai_naming);
    var list = text(area, 'ul', '');
    list.className = 'wt-rule-report-list';
    list.title = summary.themes_note || '';
    items.forEach(function (theme) {
      var row = text(list, 'li', '');
      if (theme.name) {
        var link = document.createElement('a');
        link.textContent = theme.name;
        link.href = '/rule/edit/' + encodeURIComponent(String(theme.module).toLowerCase()) + '/' + encodeURIComponent(theme.rule_id);
        row.appendChild(link);
      } else {
        text(row, 'span', 'Rule ' + theme.rule_id);
      }
      text(row, 'span', ' · ' + (SOURCES[theme.source] || theme.source));
      var chip = text(row, 'span', String(theme.category).replace(/_/g, ' ').toLowerCase());
      chip.className = 'wt-status-chip';
      text(row, 'span', ' · ' + theme.records + ' records from ' + theme.people + (theme.people === 1 ? ' person' : ' people') +
        (theme.terms && theme.terms.length ? ' · ' + theme.terms.join(', ') : ''));
      suggestion(row, theme.ai);
    });
  }
  // R5.2b: one status chip for AI naming; the reason sits in its tooltip instead of a paragraph.
  function namingLabel(state) {
    switch (state.state) {
      case 'ON': return 'AI names: ' + state.named + ' of ' + state.themes;
      case 'OFF': return 'AI names off';
      case 'NO_API_KEY': return 'AI names: no API key';
      case 'API_KEY_REJECTED': return 'AI names: key rejected';
      case 'MODEL_UNAVAILABLE': return 'AI names: model unavailable';
      case 'BUDGET_USED': return 'AI names: budget used';
      default: return 'AI names unavailable';
    }
  }
  function naming(area, state) {
    if (!state) return;
    var label = namingLabel(state);
    var chip = text(area, 'span', label);
    chip.className = 'wt-status-chip';
    chip.title = state.message || '';
  }
  // An AI suggestion is labelled as such, rendered as text only, and explains itself in a tooltip.
  function suggestion(row, ai) {
    if (!ai) return;
    if (ai.status !== 'NAMED') {
      var rejected = text(row, 'span', 'AI output rejected');
      rejected.className = 'wt-status-chip';
      rejected.title = 'The suggestion did not pass validation and is not shown. It is not retried for this theme.';
      return;
    }
    var name = text(row, 'span', ' · AI suggestion: ' + ai.name);
    name.title = ai.explanation + ' (' + ai.model + ', ' + (window.WatchtowerTime ? window.WatchtowerTime.format(ai.created_at) : new Date(ai.created_at).toLocaleString(undefined, {timeZoneName: 'short'})) +
      (ai.text_sent ? '' : '; named from counts only') + ')';
    var cause = text(row, 'span', 'likely: ' + (ai.cause_label || ai.cause));
    cause.className = 'wt-status-chip';
  }
  function matrix(summary) {
    var area = element('matrix');
    if (!area) return; // no saved report yet: the Coverage tab shows live data only
    area.replaceChildren();
    if (!summary || !summary.matrix || !summary.matrix.rows || !summary.matrix.rows.length) {
      empty(area, 'shield', 'No coverage data in this report', 'Which CWE categories rules map to, and whether their engines ran. A CWE mapping or a run is not proof a vulnerability would be caught.');
      return;
    }
    var data = summary.matrix;
    if (element('note')) element('note').setAttribute('data-tip', data.note + ' CWE Top 25 edition ' + data.cwe_edition + '.');
    var table = text(area, 'table', '');
    table.className = 'wt-results-table wt-rule-report-matrix';
    var head = text(text(table, 'thead', ''), 'tr', '');
    text(head, 'th', 'CWE').scope = 'col';
    data.languages.forEach(function (language) { text(head, 'th', language).scope = 'col'; });
    var body = text(table, 'tbody', '');
    data.rows.forEach(function (row) {
      var tr = text(body, 'tr', '');
      var empty = Object.keys(row.cells).length === 0;
      if (row.rank && empty) tr.className = 'is-gap';
      var th = text(tr, 'th', (row.rank ? '#' + row.rank + ' ' : '') + row.cwe + (row.name ? ' ' + row.name : ''));
      th.scope = 'row';
      data.languages.forEach(function (language) {
        var cell = row.cells[language];
        text(tr, 'td', cell ? cell.rules + ' rule' + (cell.rules === 1 ? '' : 's') + ' · ' + cell.ran_30d + ' ran' : '—');
      });
    });
  }
  // The page draws the report's name, trigger and counts on the server; the schedule dialog and the
  // themes / coverage tabs are filled here. Viewers without Rule Modify get no schedule or run controls.
  function render(data) {
    latest = data;
    var canModify = dialog().dataset.canModify === 'true';
    if (element('settings')) element('settings').hidden = !canModify;
    if (element('run')) element('run').hidden = !canModify;
    if (element('enabled')) element('enabled').checked = data.settings.enabled;
    if (element('weekday')) element('weekday').value = String(data.settings.weekday);
    if (element('schedule-label')) element('schedule-label').textContent = scheduleLabel(data.settings);
    var report = data.report;
    var summary = report && report.summary;
    if (element('counts')) element('counts').textContent = summary ? summary.counts.attention + ' of ' + summary.counts.rules + ' rules need attention' : '';
    if (!dialog().hasAttribute('data-rule-report-page')) attention(summary);
    themes(summary);
    matrix(summary);
  }
  async function open() {
    var target = dialog();
    if (!target) return;
    if (!target.hasAttribute('data-rule-report-page')) await target.show();
    try { render(target.dataset.reportId ? await call('/rules/review-reports/' + encodeURIComponent(target.dataset.reportId) + '/data') : await api('')); } catch (e) { status(e.message); }
    try { upstream(await call('/rule/upstream-updates')); } catch (e) { if (element('upstream')) element('upstream').textContent = e.message; }
  }
  document.addEventListener('click', async function (event) {
    if (event.target.closest('[data-rule-report-open]')) { await open(); return; }
    if (!dialog() || !dialog().contains(event.target)) return;
    if (event.target.closest('[data-rule-report-close]')) { dialog().close(); return; }
    var approve = event.target.closest('[data-rule-report-approve]');
    if (approve) {
      try {
        var result = await call('/rule/upstream-updates/' + encodeURIComponent(approve.dataset.ruleReportApprove) + '/approve', {version: Number(approve.dataset.version)});
        upstream(result.updates); status('New rules can now block pull requests like other rules in their ruleset.');
      } catch (e) { status(e.message); }
      return;
    }
    if (event.target.closest('[data-rule-report-run]')) {
      status('Running…');
      try {
        var data = await api('/run', {});
        if (dialog().hasAttribute('data-rule-report-page')) {
          status('Report generated. ');var link = text(element('status'),'a','Open it');link.href = '/rules/review-reports?reportId=' + encodeURIComponent(data.report.id);
        } else render(data);
      } catch (e) { status(e.message); }
    }
  });
  document.addEventListener('submit', async function (event) {
    if (!event.target.matches('[data-rule-report-settings]')) return;
    event.preventDefault();
    try {
      var saved = await api('/settings', {enabled: element('enabled').checked, weekday: Number(element('weekday').value), version: latest.settings.version});
      if (dialog().hasAttribute('data-rule-report-page')) latest.settings = saved.settings; else render(saved);
      if (element('schedule-label')) element('schedule-label').textContent = scheduleLabel(saved.settings);
      var scheduleDialog = event.target.closest('md-dialog');
      if (scheduleDialog && typeof scheduleDialog.close === 'function') scheduleDialog.close();
      status('Schedule saved.');
    } catch (e) { status(e.message); }
  });
  function initialize(){var root=document.querySelector('[data-rule-report-page]');if(!root||root.dataset.ready)return;root.dataset.ready='true';open();}
  document.addEventListener('DOMContentLoaded',initialize);document.addEventListener('htmx:afterSwap',initialize);initialize();
})();

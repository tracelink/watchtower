(function () {
  'use strict';
  // AI review on a pull request or repository scan report: pick files (up to the server's limit), confirm, then read the points the
  // assistant noticed and mark each one confirmed, dismissed, or ask for a rule draft. It advises; it saves no code,
  // judges nothing and changes no rule. ai-helpers.js decides whether the button shows and hands over its fetch
  // helper. All text from the server is written as text, never as markup.
  var POLL_MS = 3000;
  var MAX_POLLS = 400;
  var MAX_FILES = 200;
  var TOKENS_PER_FILE = 8000;
  var SECONDS_PER_FILE = 5;
  // Past this many files a review is a big one: its cost and time are shown in the warning tone.
  var BIG_REVIEW_FILES = 10;
  var FOCUS_CHIP_CHARS = 48;
  var COVERAGE = {
    COVERED: ['ok', 'check_circle', 'Covered', 'A scanner finding of this scan is on these lines.'],
    GAP: ['bad', 'radio_button_unchecked', 'Gap', 'No scanner finding of this scan is on these lines.'],
    NOT_CHECKED: ['warn', 'help_outline', 'Not checked', 'The scan kept only some of its findings, so this could not be compared.']
  };
  var DECIDED = {CONFIRMED: ['check', 'Confirmed'], DISMISSED: ['block', 'Dismissed'], DRAFTED: ['build', 'Rule drafted']};
  var SCANNERS = {pmd: 'PMD', opengrep: 'Opengrep', regex: 'Regex', eslint: 'ESLint', json: 'JSON'};
  var DESIGNER_URL = /^\/designer\/(pmd|opengrep|regex|eslint|json)\?draft=[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;

  function make(tag, className, value) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined && value !== null) node.textContent = value;
    return node;
  }
  function icon(name) {
    var node = make('span', 'material-icons', name);
    node.setAttribute('aria-hidden', 'true');
    return node;
  }
  function chip(parent, iconName, label, tone, tip) {
    var node = make('span', 'wt-mini-chip' + (tone ? ' wt-mini-chip--' + tone : ''));
    if (tip) { node.tabIndex = 0; node.setAttribute('data-tip', tip); }
    if (iconName) node.appendChild(icon(iconName));
    node.appendChild(make('span', '', label));
    parent.appendChild(node);
    return node;
  }
  function plural(count, one, many) { return count + ' ' + (count === 1 ? one : many); }
  function iconButton(name, label, action, id) {
    var button = make('button', 'wt-icon-action');
    button.type = 'button';
    button.setAttribute('aria-label', label);
    button.setAttribute('data-tip', label);
    button.setAttribute('data-ai-review-act', action);
    button.setAttribute('data-item', id);
    button.appendChild(icon(name));
    return button;
  }

  function bind(button, helpers) {
    var scope = document.querySelector('[data-scan-type][data-scan-id]');
    if (!scope || !/^(pull_request|repository)$/.test(scope.dataset.scanType)) { button.remove(); return; }
    var workspace = button.closest('[data-finding-workspace]') || document;
    var pick = workspace.querySelector('[data-ai-review-pick]');
    var results = workspace.querySelector('[data-ai-review-results]');
    var chipEl = workspace.querySelector('[data-ai-review-chip]');
    if (!pick || !results || !chipEl) { button.remove(); return; }
    var type = scope.dataset.scanType;
    var id = Number(scope.dataset.scanId);
    var api = helpers.api;
    var draftsOn = false;
    var limit = MAX_FILES;
    var runId = null;
    var polls = 0;
    var timer = null;
    var opened = {};
    var parts = {
      limits: pick.querySelector('[data-ai-review-limits]'), files: pick.querySelector('[data-ai-review-files]'),
      filter: pick.querySelector('[data-ai-review-filter]'), confirm: pick.querySelector('[data-ai-review-confirm]'),
      status: pick.querySelector('[data-ai-review-status]'), start: pick.querySelector('[data-ai-review-start]'),
      selectBar: pick.querySelector('[data-ai-review-select]'), focus: pick.querySelector('[data-ai-review-focus]'),
      focusState: pick.querySelector('[data-ai-review-focus-state]'), focusBox: pick.querySelector('[data-ai-review-focus-box]'),
      startLabel: pick.querySelector('[data-ai-review-start-label]'), summary: results.querySelector('[data-ai-review-summary]'),
      points: results.querySelector('[data-ai-review-points]'), note: results.querySelector('[data-ai-review-note]'),
      resume: results.querySelector('[data-ai-review-resume]')
    };
    if (helpers.flags) helpers.flags().then(function (flags) { draftsOn = !!flags.ruleDraft; });

    // ---- picking the files
    function selected() { return Array.prototype.slice.call(parts.files.querySelectorAll('input[type=checkbox]:checked')); }
    // A message under the files; a refusal or a note about the limit is brought into view, since the buttons are below the list.
    function say(text) {
      parts.status.textContent = text;
      if (text && typeof parts.status.scrollIntoView === 'function') parts.status.scrollIntoView({block: 'nearest'});
    }
    function syncPick() {
      var chosen = selected().length;
      Array.prototype.forEach.call(parts.files.querySelectorAll('input[type=checkbox]'), function (box) { box.disabled = !box.checked && chosen >= limit; });
      parts.start.disabled = chosen === 0;
      parts.startLabel.textContent = chosen ? 'Review ' + plural(chosen, 'file', 'files') : 'Review';
      parts.confirm.replaceChildren();
      if (!chosen) return;
      var big = chosen > BIG_REVIEW_FILES;
      var minutes = Math.max(1, Math.round(chosen * SECONDS_PER_FILE / 60));
      chip(parts.confirm, 'token', 'Up to ' + (chosen * TOKENS_PER_FILE).toLocaleString('en-US') + ' tokens', big ? 'warn' : '',
        (big ? 'A big review. ' : '') + 'Each file is sent on its own, cut to its first 800 lines. The daily AI share for code review pays for it; if it runs out the review stops where it is and can be resumed.');
      chip(parts.confirm, 'schedule', 'About ' + minutes + ' min', big ? 'warn' : '',
        'Files are read one at a time in the background. You can leave the page' + (big ? ' and come back through the chip.' : '.'));
      chip(parts.confirm, 'lock', 'Secret lines removed', '', 'Lines where a scanner recorded a secret are replaced before anything is sent, and are never reported on.');
      chip(parts.confirm, 'folder_off', 'Code not kept', '', 'Only the file names, line numbers, a weakness and one sentence are saved, for 30 days.');
    }
    // ---- selecting many files at once
    function rows() { return Array.prototype.slice.call(parts.files.querySelectorAll('tr[data-path]')); }
    function updateCounts() {
      if (!parts.selectBar) return;
      var all = rows();
      parts.selectBar.hidden = all.length === 0;
      var withFindings = parts.selectBar.querySelector('[data-ai-review-count="findings"]');
      var shown = parts.selectBar.querySelector('[data-ai-review-count="shown"]');
      if (withFindings) withFindings.textContent = String(all.filter(function (row) { return Number(row.dataset.findings) > 0; }).length);
      if (shown) shown.textContent = String(all.filter(function (row) { return !row.hidden; }).length);
    }
    // Ticks the rows that qualify, up to the limit, and says so when some were left out.
    function tick(qualifies) {
      var room = limit - selected().length;
      var added = 0;
      var left = 0;
      rows().filter(qualifies).forEach(function (row) {
        var box = row.querySelector('input[type=checkbox]');
        if (box.checked) return;
        if (added < room) { box.checked = true; added++; } else { left++; }
      });
      syncPick();
      say(left ? 'Ticked ' + plural(added, 'file', 'files') + '; ' + left + ' left out because a review reads at most ' + limit + ' files. Narrow the filter to choose others.' : '');
    }
    if (parts.selectBar) {
      parts.selectBar.addEventListener('click', function (event) {
        var action = event.target.closest('[data-ai-review-select-action]');
        if (!action) return;
        var which = action.getAttribute('data-ai-review-select-action');
        if (which === 'clear') {
          selected().forEach(function (box) { box.checked = false; });
          syncPick();
          say('');
        } else if (which === 'findings') {
          tick(function (row) { return Number(row.dataset.findings) > 0; });
        } else if (which === 'shown') {
          tick(function (row) { return !row.hidden; });
        }
      });
    }

    // ---- the optional focus
    function focusText() { return String((parts.focus && parts.focus.value) || '').trim(); }
    function drawFocus() {
      if (!parts.focusState) return;
      var set = focusText() !== '';
      parts.focusState.className = 'wt-mini-chip' + (set ? ' wt-mini-chip--ok' : '');
      parts.focusState.replaceChildren(icon(set ? 'tune' : 'edit_note'), make('span', '', set ? 'Set' : 'Optional'));
    }
    if (parts.focus) parts.focus.addEventListener('input', drawFocus);

    function drawFiles(data) {
      parts.files.replaceChildren();
      parts.limits.replaceChildren();
      limit = data.max_files || MAX_FILES;
      var list = data.files || [];
      if (!list.length) {
        var none = make('div', 'wt-empty-picture');
        none.appendChild(icon('folder_open'));
        none.appendChild(make('strong', '', 'No files to choose from'));
        none.appendChild(make('span', 'wt-muted', type === 'pull_request' ? 'This pull request changed no source files.' : 'This scan has no source files to choose from.'));
        parts.files.appendChild(none);
        updateCounts();
        syncPick();
        return;
      }
      chip(parts.limits, 'checklist', 'Choose up to ' + limit, '', 'The review reads whole files, so it is limited to ' + limit + ' at a time.');
      var table = make('table', 'table mb-0');
      var body = make('tbody');
      list.forEach(function (file) {
        var row = make('tr');
        row.setAttribute('data-path', file.path.toLowerCase());
        row.setAttribute('data-findings', String(file.findings || 0));
        var cell = make('td');
        var label = make('label', 'wt-checkbox-row');
        var box = make('input');
        box.type = 'checkbox';
        box.value = file.path;
        box.setAttribute('aria-label', 'Review ' + file.path);
        box.addEventListener('change', syncPick);
        label.appendChild(box);
        label.appendChild(make('span', '', file.path));
        cell.appendChild(label);
        row.appendChild(cell);
        var facts = make('td');
        if (file.changed) chip(facts, 'edit', 'Changed', '', 'This file was changed by the pull request.');
        if (file.findings) chip(facts, 'bug_report', String(file.findings), 'warn', plural(file.findings, 'scanner finding', 'scanner findings') + ' in this file');
        row.appendChild(facts);
        body.appendChild(row);
      });
      table.appendChild(body);
      parts.files.appendChild(table);
      updateCounts();
      syncPick();
    }
    async function openPick() {
      parts.status.textContent = 'Loading files…';
      parts.files.replaceChildren();
      parts.confirm.replaceChildren();
      parts.start.disabled = true;
      pick.show();
      try {
        drawFiles(await api('/assistant/ai-review/files/' + type + '/' + id));
        parts.status.textContent = '';
      } catch (e) {
        parts.status.textContent = e.message;
      }
    }
    parts.filter.addEventListener('input', function () {
      var needle = String(parts.filter.value || '').toLowerCase();
      Array.prototype.forEach.call(parts.files.querySelectorAll('tr[data-path]'), function (row) { row.hidden = needle !== '' && row.dataset.path.indexOf(needle) < 0; });
      updateCounts();
    });
    parts.start.addEventListener('click', async function () {
      var paths = selected().map(function (box) { return box.value; });
      if (!paths.length) return;
      parts.start.disabled = true;
      parts.status.textContent = 'Starting…';
      var body = {scanType: type, scanId: id, paths: paths};
      var focus = focusText();
      if (focus) body.focus = focus;
      try {
        var view = await api('/assistant/ai-review', 'POST', body);
        if (!view.run_id) { say(view.message || 'The review is not available right now.'); syncPick(); return; }
        parts.status.textContent = '';
        pick.close();
        runId = view.run_id;
        polls = 0;
        show(view);
        results.show();
      } catch (e) {
        // A refused focus opens its box, so the person sees what to change.
        if (parts.focusBox && /focus/i.test(e.message)) parts.focusBox.open = true;
        say(e.message);
        syncPick();
      }
    });

    // ---- reading the result
    function drawChip(view) {
      var state = view.state;
      chipEl.hidden = state === 'NONE';
      if (state === 'NONE') return;
      var busy = state === 'QUEUED' || state === 'RUNNING';
      var gaps = (view.items || []).filter(function (item) { return item.coverage === 'GAP' && item.state === 'OPEN'; }).length;
      chipEl.className = 'wt-mini-chip wt-mini-chip--link ' + (busy ? 'wt-ai-triage-chip' : state === 'DONE' ? (gaps ? 'wt-mini-chip--warn' : 'wt-mini-chip--ok') : 'wt-mini-chip--warn');
      chipEl.querySelector('[data-ai-review-icon]').textContent = busy ? 'autorenew' : state === 'DONE' ? (gaps ? 'manage_search' : 'check_circle') : 'pause_circle';
      chipEl.querySelector('[data-ai-review-text]').textContent = busy ? 'AI review ' + view.files_done + '/' + view.files_total
        : state === 'DONE' ? 'AI review · ' + plural(view.items_total, 'point', 'points') : 'AI review stopped';
      chipEl.setAttribute('aria-label', chipEl.querySelector('[data-ai-review-text]').textContent);
      chipEl.setAttribute('data-tip', busy ? 'Reading the files in the background. You can leave this page.'
        : 'Open the last AI review of this scan' + (gaps ? ': ' + plural(gaps, 'point', 'points') + ' not covered by a scanner finding.' : '.'));
    }
    function drawSummary(view) {
      parts.summary.replaceChildren();
      var state = view.state;
      var busy = state === 'QUEUED' || state === 'RUNNING';
      if (busy) chip(parts.summary, 'autorenew', 'Reading ' + view.files_done + '/' + view.files_total + ' files', 'info', 'Working through the files one at a time. You can close this and come back.');
      else if (state === 'DONE') chip(parts.summary, 'check_circle', plural(view.files_done, 'file', 'files') + ' read', 'ok', 'The review finished.');
      else if (state === 'PARTIAL_BUDGET') chip(parts.summary, 'hourglass_empty', 'Stopped: daily share used up', 'warn', 'AI code review has used its daily share. Chat is not affected. Resume to read the rest.');
      else chip(parts.summary, 'info', 'Stopped', 'warn', 'The review stopped before it finished. Resume to read the files that are left.');
      var gaps = (view.items || []).filter(function (item) { return item.coverage === 'GAP'; }).length;
      if (view.items_total) chip(parts.summary, 'manage_search', plural(view.items_total, 'point', 'points'), '', 'What the assistant noticed in the files you picked.');
      if (gaps) chip(parts.summary, 'radio_button_unchecked', plural(gaps, 'gap', 'gaps'), 'bad', 'Points that no scanner finding of this scan sits on.');
      if (view.focus) {
        var shortFocus = view.focus.length > FOCUS_CHIP_CHARS ? view.focus.substring(0, FOCUS_CHIP_CHARS - 1) + '…' : view.focus;
        chip(parts.summary, 'tune', 'Focus: ' + shortFocus, '', 'Focus given to the assistant: ' + view.focus);
      }
      (view.files || []).filter(function (file) { return file.status === 'SKIPPED' || file.status === 'NO_ANSWER'; }).forEach(function (file) {
        chip(parts.summary, 'report_problem', file.path, 'warn', file.note || 'This file was not reviewed.');
      });
      parts.resume.hidden = !(state === 'PARTIAL_BUDGET' || state === 'FAILED');
      parts.note.textContent = view.note || '';
    }
    function drawPoints(view) {
      parts.points.replaceChildren();
      var list = view.items || [];
      if (!list.length) {
        if (view.state === 'DONE') {
          var empty = make('div', 'wt-empty-picture');
          empty.appendChild(icon('task_alt'));
          empty.appendChild(make('strong', '', 'Nothing noticed'));
          empty.appendChild(make('span', 'wt-muted', 'The assistant found nothing it could point to in these files. That is not proof they are safe.'));
          parts.points.appendChild(empty);
        }
        return;
      }
      var table = make('table', 'table mb-0');
      var head = make('tr');
      ['Where and why', 'Status', ''].forEach(function (name) {
        var th = make('th', '', name);
        th.scope = 'col';
        if (!name) th.appendChild(make('span', 'visually-hidden', 'Actions'));
        head.appendChild(th);
      });
      table.appendChild(make('thead')).appendChild(head);
      var body = make('tbody');
      list.forEach(function (item) { body.appendChild(drawPoint(item)); });
      table.appendChild(body);
      parts.points.appendChild(table);
    }
    function drawPoint(item) {
      var row = make('tr');
      // The file name and lines lead, the reason sits under them, and the whole path is on hover.
      var where = make('th');
      where.scope = 'row';
      var lines = item.first_line + (item.last_line !== item.first_line ? '-' + item.last_line : '');
      var name = make('strong', '', item.path.substring(item.path.lastIndexOf('/') + 1) + ':' + lines);
      name.tabIndex = 0;
      name.setAttribute('data-tip', item.path + ', lines ' + lines);
      where.appendChild(name);
      where.appendChild(make('div', 'wt-muted fw-normal', item.rationale));
      row.appendChild(where);
      var status = make('td');
      var coverage = COVERAGE[item.coverage] || COVERAGE.NOT_CHECKED;
      chip(status, coverage[1], coverage[2], coverage[0], coverage[3] + (item.covered_by ? ' (' + item.covered_by + ')' : ''));
      chip(status, 'shield', item.cwe, item.confidence === 'low' ? 'warn' : '', (item.cwe_name ? item.cwe_name + '. ' : '') + item.confidence + ' confidence.'
        + (item.scanner ? ' ' + SCANNERS[item.scanner] + ' could catch this.' : ''));
      row.appendChild(status);
      var actions = make('td');
      actions.className = 'text-end text-nowrap';
      var decided = DECIDED[item.state];
      if (decided) chip(actions, decided[0], decided[1], '', 'A person decided this; the assistant decides nothing.');
      if (opened[item.id]) {
        var link = make('a', 'wt-mini-chip wt-mini-chip--link');
        link.href = opened[item.id];
        link.appendChild(icon('open_in_new'));
        link.appendChild(make('span', '', 'Open draft'));
        actions.appendChild(link);
      } else if (draftsOn && item.can_draft && item.state !== 'DRAFTED') {
        actions.appendChild(iconButton('build', 'Draft a rule for this', 'draft', item.id));
      }
      if (item.state !== 'CONFIRMED') actions.appendChild(iconButton('check', 'Confirm: this is a real weakness', 'confirm', item.id));
      if (item.state !== 'DISMISSED') actions.appendChild(iconButton('close', 'Dismiss: this is not a problem', 'dismiss', item.id));
      row.appendChild(actions);
      return row;
    }
    function show(view) {
      drawChip(view);
      if (view.state === 'NONE') return;
      runId = view.run_id;
      drawSummary(view);
      drawPoints(view);
      var busy = view.state === 'QUEUED' || view.state === 'RUNNING';
      window.clearTimeout(timer);
      if (busy && polls++ < MAX_POLLS) timer = window.setTimeout(refresh, POLL_MS);
    }
    async function refresh() {
      try { show(await api('/assistant/ai-review/runs/' + encodeURIComponent(runId))); } catch (e) { /* the next poll tries again */ }
    }

    // ---- what a person does with a point
    results.addEventListener('click', async function (event) {
      var target = event.target instanceof Element ? event.target.closest('[data-ai-review-act]') : null;
      if (!target) return;
      target.disabled = true;
      parts.note.textContent = '';
      try {
        var answer = await api('/assistant/ai-review/items/' + encodeURIComponent(target.dataset.item) + '/' + target.dataset.aiReviewAct, 'POST');
        if (target.dataset.aiReviewAct === 'draft') {
          if (answer.state === 'OK' && DESIGNER_URL.test(String(answer.url))) opened[target.dataset.item] = answer.url;
          else { parts.note.textContent = answer.message || 'A rule draft is not available right now.'; target.disabled = false; return; }
        }
        await refresh();
      } catch (e) {
        parts.note.textContent = e.message;
        target.disabled = false;
      }
    });
    parts.resume.addEventListener('click', async function () {
      parts.resume.disabled = true;
      try { polls = 0; show(await api('/assistant/ai-review/runs/' + encodeURIComponent(runId) + '/resume', 'POST')); }
      catch (e) { parts.note.textContent = e.message; }
      finally { parts.resume.disabled = false; }
    });
    chipEl.addEventListener('click', function () { results.show(); });
    button.addEventListener('click', openPick);

    // The last review of this scan, if there is one.
    api('/assistant/ai-review/scan/' + type + '/' + id).then(show).catch(function () { /* no review yet, or not allowed */ });
  }

  window.WatchtowerAiReview = {bind: bind};
})();

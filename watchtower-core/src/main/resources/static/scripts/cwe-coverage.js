(function () {
  'use strict';
  // Review reports, Coverage tab: the weaknesses in the CWE profile against the languages, with a chip per
  // cell (Covered, Weak, Gap or a person's decision). The server works out every cell; this script draws
  // the table, edits the profile and records decisions about gaps. Text from the server is only ever
  // written as text, never as markup.
  var root = document.querySelector('[data-cwe-coverage]');
  if (!root || root.dataset.covReady) return;
  root.dataset.covReady = 'true';
  var BASE = '/rules/coverage';
  var SEARCH_DELAY_MS = 250;
  var MIN_QUERY = 2;
  var page = document.querySelector('[data-rule-report-page]') || root;
  var canModify = root.dataset.canModify === 'true';
  var PRIORITY = {
    CRITICAL: {tone: 'danger', label: 'Critical'},
    HIGH: {tone: 'warning', label: 'High'},
    NORMAL: {tone: 'neutral', label: 'Normal'}
  };
  var NEXT_PRIORITY = {CRITICAL: 'HIGH', HIGH: 'NORMAL', NORMAL: 'CRITICAL'};
  var DECISION = {
    NOT_COVERABLE: {icon: 'block', label: 'Not coverable'},
    NOT_APPLICABLE: {icon: 'do_not_disturb_on', label: 'Not applicable'},
    DEFERRED: {icon: 'schedule', label: 'Deferred'}
  };
  var data = null;
  var searchTimer = null;
  var searchRound = 0;
  var gap = null;

  function find(selector) { return document.querySelector(selector); }
  function make(tag, className, value) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined && value !== null) node.textContent = value;
    return node;
  }
  function icon(name, extra) {
    var node = make('span', 'material-icons' + (extra ? ' ' + extra : ''), name);
    node.setAttribute('aria-hidden', 'true');
    return node;
  }
  function chip(parent, options) {
    var node = make(options.button ? 'button' : 'span',
      'wt-mini-chip' + (options.tone ? ' wt-mini-chip--' + options.tone : '') + (options.button ? ' wt-mini-chip--link' : ''));
    if (options.button) node.type = 'button'; else node.tabIndex = 0;
    if (options.tip) node.setAttribute('data-tip', options.tip);
    if (options.icon) node.appendChild(icon(options.icon));
    node.appendChild(make('span', '', options.label));
    if (options.count !== undefined) node.appendChild(make('span', 'wt-count-badge', String(options.count)));
    parent.appendChild(node);
    return node;
  }
  function plural(count, word) { return count + ' ' + word + (count === 1 ? '' : 's'); }
  function say(message) {
    var dialog = find('[data-cov-profile-dialog]');
    var target = dialog && dialog.open ? dialog.querySelector('[data-cov-error]') : find('[data-rule-report-status]');
    if (target) target.textContent = message;
  }

  async function request(path, params) {
    var options = {headers: {Accept: 'application/json'}};
    if (params) {
      options.method = 'POST';
      options.headers[page.dataset.csrfHeader] = page.dataset.csrfToken;
      options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
      options.body = new URLSearchParams(params).toString();
    }
    var response = await window.fetch(path, options);
    var body = {};
    try { body = await response.json(); } catch (e) { body = {}; }
    if (!response.ok) throw new Error(body.error || 'That did not work (' + response.status + ').');
    return body;
  }

  function cellTip(cell, clickable) {
    var names = cell.rules.map(function (rule) { return rule.name; });
    if (cell.status === 'COVERED') {
      var more = cell.ruleCount > names.length ? ' · +' + (cell.ruleCount - names.length) + ' more' : '';
      return plural(cell.ruleCount, 'rule') + '\n' + names.join(' · ') + more;
    }
    if (cell.status === 'WEAK') {
      return plural(cell.ruleCount, 'rule') + ', none working well\n' + cell.rules.map(function (rule) {
        return rule.name + (rule.reason ? ': ' + rule.reason : '');
      }).join('\n');
    }
    if (cell.status === 'GAP') {
      return 'No active rule for this weakness in this language.' + (clickable ? ' Click to decide what to do.' : '');
    }
    var decision = DECISION[cell.status];
    var who = cell.decidedBy ? 'Marked by ' + cell.decidedBy + '.' : '';
    return [decision ? decision.label : cell.status, cell.decisionNote, who].filter(Boolean).join('\n');
  }

  function drawCell(cell, row, column) {
    var td = make('td');
    if (cell.status === 'NONE') {
      td.className = 'wt-muted';
      td.textContent = '—';
      return td;
    }
    var look = {COVERED: ['check_circle', 'ok'], WEAK: ['report_problem', 'warn'], GAP: ['radio_button_unchecked', 'bad']}[cell.status];
    var decision = DECISION[cell.status];
    var clickable = canModify && (cell.status === 'GAP' || !!decision);
    var node = chip(td, {
      button: clickable,
      tone: look ? look[1] : '',
      icon: look ? look[0] : decision.icon,
      label: look ? (cell.status === 'GAP' ? 'Gap' : String(cell.ruleCount)) : decision.label,
      tip: cellTip(cell, clickable)
    });
    if (clickable) {
      node.setAttribute('data-cov-gap', '');
      node.setAttribute('data-cwe', row.label);
      node.setAttribute('data-language', column.key);
    }
    return td;
  }

  function drawTable() {
    var area = find('[data-cov-table]');
    area.replaceChildren();
    if (!data.rows.length) {
      var box = make('div', 'wt-empty-picture');
      box.appendChild(icon('shield', 'wt-empty-picture__icon'));
      box.appendChild(make('strong', '', 'No CWE profile yet'));
      box.appendChild(make('span', 'wt-muted', 'Choose the weaknesses that matter here to see which have a rule.'));
      if (canModify) {
        var actions = make('div', 'wt-meta-chips');
        var top = make('md-outlined-button', '', 'Add the 2024 Top 25');
        top.setAttribute('data-cov-top25', '');
        var choose = make('md-outlined-button', '', 'Choose weaknesses');
        choose.setAttribute('data-cov-open-profile', '');
        actions.appendChild(top);
        actions.appendChild(choose);
        box.appendChild(actions);
      }
      area.appendChild(box);
      return;
    }
    var table = make('table', 'table mb-0');
    table.appendChild(make('caption', 'visually-hidden', 'Profile CWEs by language'));
    var head = make('tr');
    var weakness = make('th', '', 'Weakness');
    weakness.scope = 'col';
    head.appendChild(weakness);
    data.columns.forEach(function (column) {
      var th = make('th', '', column.label);
      th.scope = 'col';
      head.appendChild(th);
    });
    table.appendChild(make('thead')).appendChild(head);
    var body = make('tbody');
    data.rows.forEach(function (row) {
      var tr = make('tr');
      var th = make('th');
      th.scope = 'row';
      var label = make('span', 'wt-work-rule');
      var priority = PRIORITY[row.priority] || PRIORITY.NORMAL;
      var dot = icon('circle', 'rv-dot wt-tone-' + priority.tone);
      dot.setAttribute('data-tip', priority.label + ' in your profile');
      dot.tabIndex = 0;
      label.appendChild(dot);
      var name = make('span', '', row.label + (row.name ? ' ' + row.name : ''));
      if (row.note) name.setAttribute('data-tip', row.note);
      label.appendChild(name);
      th.appendChild(label);
      tr.appendChild(th);
      data.columns.forEach(function (column) {
        var cell = row.cells.filter(function (candidate) { return candidate.language === column.key; })[0];
        tr.appendChild(cell ? drawCell(cell, row, column) : make('td', 'wt-muted', '—'));
      });
      body.appendChild(tr);
    });
    table.appendChild(body);
    area.appendChild(table);
  }

  function drawChips() {
    var area = find('[data-cov-chips]');
    area.replaceChildren();
    chip(area, {icon: 'help_outline', label: 'How to read this',
      tip: 'Coverage compares the CWEs in your profile with the rules that exist for each language. A rule counts when it is active, has run in the last 30 days and is not noisy. This tab is live, not the saved snapshot.'});
    var profile = chip(area, {button: canModify, icon: 'tune', label: 'Profile · ' + plural(data.rows.length, 'CWE'),
      tip: canModify ? 'The weaknesses that matter in your environment. Click to edit.' : 'The weaknesses that matter in your environment.'});
    if (canModify) profile.setAttribute('data-cov-open-profile', '');
    if (!data.rows.length) return;
    chip(area, {tone: 'ok', icon: 'check_circle', label: 'Covered', count: data.counts.covered,
      tip: 'At least one active rule that has run recently and is not noisy'});
    chip(area, {tone: 'warn', icon: 'report_problem', label: 'Weak', count: data.counts.weak,
      tip: 'A rule exists, but it has not run for 30 days, is noisy or its scanner is off'});
    chip(area, {tone: 'bad', icon: 'radio_button_unchecked', label: 'Gap', count: data.counts.gap,
      tip: 'No active rule for this weakness in this language'});
    if (data.counts.decided) {
      chip(area, {icon: 'block', label: 'Decided', count: data.counts.decided,
        tip: 'Marked not applicable, not coverable yet or deferred by a person'});
    }
  }

  function drawProfile() {
    var dialog = find('[data-cov-profile-dialog]');
    if (!dialog) return;
    var label = dialog.querySelector('[data-cov-profile-count-label]');
    if (label) label.textContent = data.rows.length + ' selected';
    var area = dialog.querySelector('[data-cov-entries]');
    area.replaceChildren();
    data.rows.forEach(function (row) {
      var priority = PRIORITY[row.priority] || PRIORITY.NORMAL;
      var entry = make('span', 'wt-mini-chip');
      entry.tabIndex = 0;
      entry.setAttribute('data-tip', row.label + (row.name ? ' · ' + row.name : '') + '. ' + priority.label + '. Click the dot to change the priority.');
      var dot = make('button', 'wt-icon-action');
      dot.type = 'button';
      dot.setAttribute('data-cov-priority', '');
      dot.setAttribute('data-cwe', row.label);
      dot.setAttribute('aria-label', 'Priority of ' + row.label + ': ' + priority.label + '. Change');
      dot.appendChild(icon('circle', 'rv-dot wt-tone-' + priority.tone));
      entry.appendChild(dot);
      entry.appendChild(make('span', '', row.label));
      var remove = make('button', 'wt-icon-action');
      remove.type = 'button';
      remove.setAttribute('data-cov-remove', '');
      remove.setAttribute('data-cwe', row.label);
      remove.setAttribute('aria-label', 'Remove ' + row.label);
      remove.appendChild(icon('close'));
      entry.appendChild(remove);
      area.appendChild(entry);
    });
  }

  function render(coverage) {
    data = coverage;
    drawChips();
    drawTable();
    drawProfile();
  }

  async function change(path, params) {
    try {
      var answer = await request(BASE + path, params);
      render(answer.coverage || answer);
      return answer;
    } catch (error) {
      say(error.message);
      return null;
    }
  }

  async function search(query) {
    var dialog = find('[data-cov-profile-dialog]');
    var area = dialog.querySelector('[data-cov-results]');
    var round = ++searchRound;
    if (query.trim().length < MIN_QUERY && !/^\d+$/.test(query.trim())) {
      area.replaceChildren();
      return;
    }
    try {
      var found = await request(BASE + '/search?q=' + encodeURIComponent(query.trim()));
      if (round !== searchRound) return;
      area.replaceChildren();
      if (!found.length) {
        chip(area, {icon: 'search_off', label: 'No match in the catalog',
          tip: 'Try the CWE number, or load the CWE catalog on the Knowledge page.'});
        return;
      }
      found.forEach(function (entry) {
        var node = chip(area, {button: true, tone: entry.discouraged ? 'warn' : '', icon: 'add', label: entry.label + ' ' + entry.name,
          tip: entry.discouraged ? 'MITRE discourages mapping new rules to this weakness. Click to add it anyway.' : 'Click to add to the profile'});
        node.setAttribute('data-cov-add', '');
        node.setAttribute('data-cwe', entry.label);
      });
    } catch (error) {
      say(error.message);
    }
  }

  function openGap(cwe, language) {
    var dialog = find('[data-cov-gap-dialog]');
    var row = data.rows.filter(function (candidate) { return candidate.label === cwe; })[0];
    var column = data.columns.filter(function (candidate) { return candidate.key === language; })[0];
    var cell = row && row.cells.filter(function (candidate) { return candidate.language === language; })[0];
    if (!dialog || !cell) return;
    gap = {cwe: row.label, language: language};
    dialog.querySelector('[data-cov-gap-title]').textContent = [row.label, row.name, column.label].filter(Boolean).join(' · ');
    var state = dialog.querySelector('[data-cov-gap-state]');
    state.replaceChildren();
    var decision = DECISION[cell.status];
    if (decision) chip(state, {icon: decision.icon, label: decision.label, tip: cellTip(cell, false)});
    else chip(state, {tone: 'bad', icon: 'radio_button_unchecked', label: 'No active rule', tip: cellTip(cell, false)});
    // The assistant helper in this dialog reads which gap it is about; it drafts for the first-wave languages only.
    dialog.dataset.cwe = row.label;
    dialog.dataset.language = language;
    var suggest = dialog.querySelector('[data-gap-suggest]');
    if (suggest) suggest.hidden = language === 'OTHER';
    var suggestion = dialog.querySelector('[data-gap-suggestion]');
    if (suggestion) suggestion.replaceChildren();
    dialog.querySelector('[data-cov-note]').value = cell.decisionNote || '';
    dialog.querySelector('[data-cov-clear]').hidden = !decision;
    dialog.querySelector('[data-cov-gap-error]').textContent = '';
    dialog.show();
  }

  async function decide(decision) {
    var dialog = find('[data-cov-gap-dialog]');
    var params = {cwe: gap.cwe, language: gap.language};
    var path = '/decision/clear';
    if (decision) {
      path = '/decision';
      params.decision = decision;
      params.note = dialog.querySelector('[data-cov-note]').value || '';
    }
    try {
      render(await request(BASE + path, params));
      dialog.close();
    } catch (error) {
      dialog.querySelector('[data-cov-gap-error]').textContent = error.message;
    }
  }

  document.addEventListener('click', async function (event) {
    if (!(event.target instanceof Element) || !root.isConnected) return;
    var target = event.target;
    var open = target.closest('[data-cov-open-profile]');
    if (open) {
      var profile = find('[data-cov-profile-dialog]');
      if (profile) profile.show();
      return;
    }
    var cell = target.closest('[data-cov-gap]');
    if (cell) { openGap(cell.dataset.cwe, cell.dataset.language); return; }
    var decided = target.closest('[data-cov-decide]');
    if (decided && gap) { await decide(decided.dataset.covDecide); return; }
    if (target.closest('[data-cov-clear]') && gap) { await decide(null); return; }
    if (target.closest('[data-cov-top25]')) {
      var added = await change('/profile/top25', {});
      if (added) say(added.added ? 'Added ' + added.added + ' to the profile.' : 'The Top 25 are already in the profile.');
      return;
    }
    var add = target.closest('[data-cov-add]');
    if (add) {
      var dialog = find('[data-cov-profile-dialog]');
      var done = await change('/profile', {cwe: add.dataset.cwe, priority: 'NORMAL'});
      if (done && dialog) {
        dialog.querySelector('[data-cov-search]').value = '';
        dialog.querySelector('[data-cov-results]').replaceChildren();
        dialog.querySelector('[data-cov-error]').textContent = '';
      }
      return;
    }
    var priority = target.closest('[data-cov-priority]');
    if (priority) {
      var row = data.rows.filter(function (candidate) { return candidate.label === priority.dataset.cwe; })[0];
      if (row) await change('/profile', {cwe: row.label, priority: NEXT_PRIORITY[row.priority] || 'NORMAL', note: row.note || ''});
      return;
    }
    var remove = target.closest('[data-cov-remove]');
    if (remove && window.confirm('Remove ' + remove.dataset.cwe + ' from the profile? Its gap decisions are removed too.')) {
      await change('/profile/remove', {cwe: remove.dataset.cwe});
    }
  });

  document.addEventListener('input', function (event) {
    if (!(event.target instanceof Element) || !event.target.matches('[data-cov-search]')) return;
    var query = event.target.value || '';
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(function () { search(query); }, SEARCH_DELAY_MS);
  });

  async function load() {
    try {
      render(await request(BASE));
    } catch (error) {
      var area = find('[data-cov-table]');
      area.replaceChildren(make('span', 'wt-muted', error.message));
    }
  }

  if (!root.hidden) load();
})();

/*
 * Suggest a rule improvement (Improve board, 2026-10-22): Evidence → Proposal → Save draft, one
 * step at a time. Evidence is five plain-word tiles built from the bounded sample manifest; a
 * proposal reads as a before/after card with a short Why list whose reasons cite their evidence.
 * Generating is only offered once a person has reviewed something; nothing here runs tests or
 * changes the live rule.
 */
(function () {
  'use strict';
  var root = document.querySelector('[data-rule-improvements]');
  if (!root || root.dataset.ready) return;
  root.dataset.ready = 'true';

  var POLL_MS = 1500;
  var RUNNING = ['QUEUED', 'RUNNING', 'RECOVERING'];
  var OLDER_TIP = ' "Older" means records from an earlier version of the rule; they are kept apart because the rule has changed since.';
  var KINDS = [
    {kind: 'TRUE_POSITIVE', label: 'Confirmed real', icon: 'verified', tone: 'ok', what: 'People marked the finding as a real problem.'},
    {kind: 'FALSE_POSITIVE', label: 'False alarm', icon: 'do_not_disturb_on', tone: 'bad', what: 'People marked the finding as a false positive.'},
    {kind: 'UNKNOWN', label: 'Unsure', icon: 'help', tone: '', what: 'Reviewed, but nobody could decide.'},
    {kind: 'SAVED_REVIEWS', label: 'Saved reviews', icon: 'fact_check', tone: 'info', what: 'Rule reviews saved on Saved reviews.'},
    {kind: 'MISSED_CASES', label: 'Missed cases', icon: 'flag', tone: 'warn', what: 'Vulnerabilities people reported that the rule missed.'}
  ];
  var CITATIONS = {
    feedback: {icon: 'rate_review', label: 'Reviewed finding'},
    review: {icon: 'fact_check', label: 'Saved review'},
    miss: {icon: 'flag', label: 'Missed case'},
    knowledge: {icon: 'menu_book', label: 'Approved knowledge'},
    rule: {icon: 'rule', label: 'Current rule'},
    health: {icon: 'monitor_heart', label: 'Rule health'}
  };
  var OUTCOMES = {
    PROPOSED_CHANGE: {text: 'Proposed change', icon: 'edit_note', tone: 'info'},
    ADVICE_ONLY: {text: 'Advice only', icon: 'lightbulb', tone: ''},
    NEEDS_MORE_EVIDENCE: {text: 'Needs more evidence', icon: 'hourglass_empty', tone: 'warn'}
  };
  var FIELD_LABELS = {regexPattern: 'Matching pattern', fileExtension: 'File extension', query: 'JSONPath query', message: 'Finding message',
    properties: 'PMD properties', createFunction: 'ESLint create function', schema: 'ESLint schema', messages: 'ESLint messages',
    regex: 'Matching pattern', keywords: 'Keywords', entropy: 'Entropy', secretGroup: 'Secret group', filter: 'Filter'};

  var ruleId = root.dataset.ruleId;
  var base = '/rules/' + encodeURIComponent(ruleId) + '/improvements';
  var canModify = root.dataset.canModify === 'true';
  var chatReady = root.dataset.chatReady === 'true';
  var state = {step: 1, days: 90, language: '', evidence: null, reviewed: 0, proposal: null, busy: false, saved: null};
  var timer, pendingGenerate;

  function q(name) { return root.querySelector('[data-improvement-' + name + ']'); }
  function all(name) { return Array.from(root.querySelectorAll('[data-improvement-' + name + ']')); }
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  }
  function icon(name) { var node = el('span', 'material-icons', name); node.setAttribute('aria-hidden', 'true'); return node; }
  function chip(text, iconName, tone, tip) {
    var node = el('span', 'wt-mini-chip' + (tone ? ' wt-mini-chip--' + tone : ''));
    node.append(icon(iconName), el('span', '', text));
    if (tip) { node.tabIndex = 0; node.setAttribute('data-tip', tip); }
    return node;
  }
  function status(text) { q('status').textContent = text; }

  async function api(url, body) {
    var headers = {'Accept': 'application/json'};
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      headers[root.dataset.csrfHeader] = root.dataset.csrfToken;
    }
    var response = await fetch(url, {method: body === undefined ? 'GET' : 'POST', headers: headers,
      body: body === undefined ? undefined : JSON.stringify(body)});
    var data = await response.json();
    if (!response.ok) throw new Error(data.error || data.message || 'Request unavailable');
    return data;
  }

  /* ---- Evidence ---- */
  function counts(kind) {
    var rows = (state.evidence ? state.evidence.samples : []).filter(function (s) { return s.kind === kind; });
    var total = rows.reduce(function (sum, s) { return sum + s.total; }, 0);
    var current = rows.reduce(function (sum, s) {
      return sum + (typeof s.currentTotal === 'number' ? s.currentTotal : s.revisionScope === 'CURRENT' ? s.total : 0);
    }, 0);
    return {total: total, current: current, older: total - current};
  }

  function renderTiles() {
    var area = q('tiles');
    area.replaceChildren();
    state.reviewed = 0;
    KINDS.forEach(function (k) {
      var c = counts(k.kind);
      state.reviewed += c.total;
      var tile = el('span', 'wt-stat-tile wt-improve-tile' + (k.tone ? ' wt-improve-tile--' + k.tone : ''));
      tile.tabIndex = 0;
      tile.setAttribute('data-tip', k.what + OLDER_TIP);
      tile.setAttribute('data-improvement-tile', k.kind);
      var words = el('span');
      words.append(el('strong', '', String(c.total)), el('span', '', k.label),
        el('span', 'wt-mini-chip wt-improve-split', c.current + ' this version · ' + c.older + ' older'));
      tile.append(icon(k.icon), words);
      area.appendChild(tile);
    });
    q('empty').hidden = state.reviewed > 0;
    q('needs-evidence').hidden = state.reviewed > 0;
  }

  async function loadEvidence() {
    working(true);
    state.evidence = null;
    status('Loading evidence…');
    try {
      state.evidence = await api(base + '/evidence?days=' + encodeURIComponent(state.days) + '&language=' + encodeURIComponent(state.language));
      renderTiles();
      status(state.reviewed > 0 ? 'Evidence ready.' : 'No reviewed findings yet.');
    } catch (error) {
      status(error.message);
    } finally {
      working(false);
    }
  }

  /* ---- Steps ---- */
  function usable() {
    var p = state.proposal;
    return !!(p && p.status === 'READY' && !p.stale && p.proposal && p.proposal.outcome === 'PROPOSED_CHANGE');
  }
  function generating() {
    var p = state.proposal;
    return !!(p && p.status === 'QUEUED' && RUNNING.includes(p.turnStatus));
  }
  function proposalState() {
    var p = state.proposal;
    if (state.reviewed === 0 && !p) return 'Needs evidence';
    if (!p) return chatReady ? 'Ready to ask' : 'Chat not ready';
    if (generating()) return 'Writing…';
    if (p.stale) return 'Out of date';
    if (p.status === 'INVALID_OUTPUT') return 'Failed checks';
    if (p.status !== 'READY') return 'Stopped';
    return (OUTCOMES[p.proposal && p.proposal.outcome] || {text: 'Ready'}).text;
  }
  function unlocked(step) {
    if (step === 1) return true;
    if (step === 2) return state.reviewed > 0 || !!state.proposal;
    return usable() || !!state.saved;
  }
  function renderSteps() {
    var texts = {1: state.evidence ? state.reviewed + ' reviewed' : 'Loading…', 2: proposalState(),
      3: state.saved ? 'Saved' : usable() ? 'Ready' : 'Locked'};
    all('step').forEach(function (button) {
      var n = Number(button.dataset.improvementStep), open = unlocked(n);
      button.classList.toggle('is-active', n === state.step);
      button.classList.toggle('is-locked', !open);
      button.classList.toggle('is-ok', n === 3 && !!state.saved);
      button.setAttribute('aria-selected', String(n === state.step));
      button.setAttribute('aria-disabled', String(!open));
      root.querySelector('[data-improvement-step-state="' + n + '"]').textContent = texts[n];
    });
    all('panel').forEach(function (panel) { panel.hidden = Number(panel.dataset.improvementPanel) !== state.step; });
  }
  function go(step) {
    if (!unlocked(step) || !root.querySelector('[data-improvement-panel="' + step + '"]')) return;
    state.step = step;
    renderSteps();
  }
  function working(on) {
    state.busy = on;
    q('generate').disabled = on || !chatReady || state.reviewed === 0;
    q('next').disabled = on || state.reviewed === 0;
    all('days').forEach(function (button) { button.disabled = on; });
    renderSteps();
  }

  /* ---- Proposal ---- */
  function currentValue(field) {
    var rule = state.evidence && state.evidence.references.find(function (r) { return r.id.indexOf('rule/') === 0; });
    var definition = rule && rule.data && rule.data.definition;
    return definition ? definition[field] : undefined;
  }
  function show(value) {
    if (value === undefined) return '—';
    return typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  }
  function diff(changes) {
    var grid = el('div', 'wt-improve-diff');
    Object.keys(changes).forEach(function (field) {
      var name = FIELD_LABELS[field] || field;
      [['Current rule', currentValue(field), 'del'], ['Proposed change', changes[field], 'add']].forEach(function (side) {
        var column = el('div', 'wt-improve-diff__col');
        column.append(el('span', 'wt-improve-diff__head', side[0] + ' · ' + name),
          el('pre', 'wt-improve-code wt-improve-code--' + side[2], show(side[1])));
        grid.appendChild(column);
      });
    });
    return grid;
  }
  function citation(id, references) {
    var kind = id.split('/')[0], meta = CITATIONS[kind] || {icon: 'link', label: 'Evidence'};
    var ref = (references || []).find(function (r) { return r.id === id; }) || {};
    var tip = meta.label + ' · ' + (ref.revision ? 'revision ' + ref.revision.slice(0, 8) : 'revision unknown');
    var key = id.slice(kind.length + 1);
    var href = kind === 'review' ? '/rules/' + encodeURIComponent(ruleId) + '/reviews?reviewId=' + encodeURIComponent(key)
      : kind === 'miss' && canModify ? '/rules/' + encodeURIComponent(ruleId) + '/candidates?caseId=' + encodeURIComponent(key)
        : kind === 'health' ? '/rules/' + encodeURIComponent(ruleId) + '/health' : null;
    var node = href ? el('a', 'wt-mini-chip wt-mini-chip--link') : el('span', 'wt-mini-chip');
    if (href) node.href = href; else node.tabIndex = 0;
    node.setAttribute('data-tip', tip);
    node.append(icon(meta.icon), el('span', '', meta.label + ' (cited)'));
    return node;
  }
  function why(text, iconName, extra) {
    var row = el('div', 'wt-improve-why');
    row.append(icon(iconName), el('span', '', text));
    if (extra) row.appendChild(extra);
    return row;
  }
  function renderProposal(data) {
    state.proposal = data;
    var area = q('proposal'), outcome = q('outcome');
    area.replaceChildren();
    q('review').hidden = !data.proposal;
    if (q('use')) q('use').hidden = !usable();
    q('cancel').hidden = !generating();
    status(data.stale ? 'The rule changed since this proposal. Reload the evidence and generate again.'
      : data.status === 'INVALID_OUTPUT' ? 'The answer failed Watchtower\'s checks, so nothing was saved. Try a narrower request.'
        : generating() ? 'Writing a proposal…' : data.status === 'READY' ? 'Proposal ready to check.' : 'Generation stopped: ' + (data.error || data.turnStatus || data.status));
    renderSteps();
    if (!data.proposal) { outcome.hidden = true; return; }
    var p = data.proposal, look = OUTCOMES[p.outcome] || {text: p.outcome, icon: 'info', tone: ''};
    outcome.replaceChildren(icon(look.icon), el('span', '', look.text));
    outcome.className = 'wt-mini-chip' + (look.tone ? ' wt-mini-chip--' + look.tone : '');
    outcome.hidden = false;
    if (data.stale) area.appendChild(chip('Out of date', 'update', 'warn', 'The rule changed since this proposal. Reload the evidence and generate again.'));
    if (p.outcome === 'PROPOSED_CHANGE' && p.changes && Object.keys(p.changes).length) area.appendChild(diff(p.changes));
    var list = el('div', 'wt-improve-why-list');
    list.appendChild(el('span', 'wt-picker-label', 'Why'));
    list.appendChild(why(p.problem, 'report'));
    var cited = el('span', 'wt-meta-chips');
    p.citations.forEach(function (id) { cited.appendChild(citation(id, data.evidenceReferences)); });
    list.appendChild(why(p.expectedBenefit, 'check', cited));
    area.appendChild(list);
    var risks = el('div', 'wt-meta-chips');
    p.regressions.forEach(function (text) { risks.appendChild(chip('Risk: ' + text, 'trending_down', 'warn', 'The model\'s own note on what the change could miss.')); });
    p.limitations.forEach(function (text) { risks.appendChild(chip(text, 'info', '', 'A limit the model noted.')); });
    if (risks.childElementCount) area.appendChild(risks);
    renderFields(p);
    if (data.turnId) loadExamples(data.turnId, area);
  }
  function loadExamples(turnId, area) {
    // Illustrative examples stay in the expiring transcript only; they are never run.
    api('/assistant/turn/' + encodeURIComponent(turnId)).then(function (turn) {
      if (!turn.answer) return;
      var full;
      try { full = JSON.parse(turn.answer); } catch (ignored) { return; }
      var items = [].concat(Array.isArray(full.examples) ? full.examples : [], Array.isArray(full.proposedTests) ? full.proposedTests : []);
      if (!items.length) return;
      var fold = el('details', 'wt-form-disclosure');
      var summary = el('summary');
      summary.append(icon('science'), el('span', '', 'Illustrative examples and tests (not run)'));
      fold.appendChild(summary);
      items.forEach(function (text) { fold.appendChild(el('pre', 'wt-improve-code', text)); });
      area.appendChild(fold);
    }).catch(function () { /* Expired transcripts leave the structured decision in place. */ });
  }
  async function poll() {
    if (!state.proposal) return;
    try {
      var data = await api(base + '/' + encodeURIComponent(state.proposal.id));
      renderProposal(data);
      if (generating()) { timer = setTimeout(poll, POLL_MS); return; }
      working(false);
    } catch (error) {
      status(error.message);
      working(false);
    }
  }
  async function generate() {
    if (state.busy || state.reviewed === 0) return;
    working(true);
    clearTimeout(timer);
    state.saved = null;
    q('review').hidden = true;
    status('Preparing the evidence…');
    try {
      var ids = state.evidence.references.map(function (r) { return r.id; })
        .filter(function (id) { return id.indexOf('rule/') !== 0 && id.indexOf('health/') !== 0; });
      var payload = {days: state.days, language: state.language, question: q('question').value || '', evidenceIds: ids};
      var fingerprint = JSON.stringify(payload);
      if (!pendingGenerate || pendingGenerate.fingerprint !== fingerprint) pendingGenerate = {fingerprint: fingerprint, key: crypto.randomUUID()};
      payload.idempotencyKey = pendingGenerate.key;
      var created = await api(base, payload);
      pendingGenerate = null;
      history.replaceState(null, '', base + '?proposal=' + encodeURIComponent(created.id));
      renderProposal(created);
      poll();
    } catch (error) {
      status(error.message);
      working(false);
    }
  }

  /* ---- Save draft ---- */
  function renderFields(p) {
    var fields = q('fields');
    if (!fields) return;
    fields.replaceChildren();
    if (p.outcome !== 'PROPOSED_CHANGE') return;
    var meta = (state.evidence && state.evidence.editableFields) || {};
    Object.keys(p.changes).forEach(function (field) {
      var value = p.changes[field], type = (meta[field] && meta[field].type) || (typeof value === 'string' ? 'string' : 'json');
      var input = el('md-outlined-text-field', 'wt-improve-field');
      input.setAttribute('label', (FIELD_LABELS[field] || field) + ' (editable)');
      input.setAttribute('type', 'textarea');
      input.setAttribute('rows', '4');
      input.dataset.field = field;
      input.dataset.fieldType = type;
      input.value = type === 'string' && typeof value === 'string' ? value : JSON.stringify(value, null, 2);
      fields.appendChild(input);
    });
  }
  async function save() {
    var button = q('save');
    if (!usable() || button.disabled) return;
    button.disabled = true;
    try {
      var changes = {};
      q('fields').querySelectorAll('[data-field]').forEach(function (input) {
        changes[input.dataset.field] = input.dataset.fieldType === 'string' ? input.value : JSON.parse(input.value);
      });
      var p = state.proposal;
      var result = await api(base + '/' + encodeURIComponent(p.id) + '/candidate',
        {version: p.version, baseRevision: p.baseRevision, changes: changes, rationale: q('rationale').value || '', reviewId: null});
      state.saved = result.candidateId;
      var link = q('candidates');
      link.href = root.dataset.candidatesUrl + '?candidate=' + encodeURIComponent(result.candidateId);
      link.lastChild.textContent = 'Open saved draft';
      status('Draft saved in Candidates. Add reviewed examples and tests there.');
      renderSteps();
    } catch (error) {
      status(error instanceof SyntaxError ? 'Check the edited rule: it must be valid JSON.' : error.message);
      button.disabled = false;
    }
  }

  /* ---- Wiring ---- */
  all('step').forEach(function (button) {
    button.addEventListener('click', function () { go(Number(button.dataset.improvementStep)); });
  });
  all('days').forEach(function (button) {
    button.addEventListener('click', function () {
      if (state.busy) return;
      state.days = Number(button.dataset.improvementDays);
      all('days').forEach(function (b) {
        var on = b === button;
        b.classList.toggle('is-active', on);
        b.setAttribute('aria-pressed', String(on));
      });
      loadEvidence();
    });
  });
  function setLanguage(value) {
    state.language = (value || '').trim();
    q('language-label').textContent = 'Language: ' + (state.language || 'any');
    q('language-menu').open = false;
    loadEvidence();
  }
  q('language-apply').addEventListener('click', function () { setLanguage(q('language').value); });
  q('language-clear').addEventListener('click', function () { q('language').value = ''; setLanguage(''); });
  q('next').addEventListener('click', function () { go(2); });
  q('generate').addEventListener('click', generate);
  q('cancel').addEventListener('click', async function () {
    if (!state.proposal) return;
    try {
      await api('/assistant/turn/' + encodeURIComponent(state.proposal.turnId) + '/cancel', {});
      clearTimeout(timer);
      q('cancel').hidden = true;
      status('Generation canceled. Nothing was saved.');
      working(false);
    } catch (error) {
      status(error.message);
    }
  });
  if (q('use')) q('use').addEventListener('click', function () { go(3); });
  if (q('save')) q('save').addEventListener('click', save);
  window.addEventListener('pagehide', function () { clearTimeout(timer); });

  loadEvidence().then(function () {
    var id = new URLSearchParams(location.search).get('proposal');
    if (!id) return;
    state.proposal = {id: id};
    state.step = 2;
    working(true);
    poll();
  });
}());

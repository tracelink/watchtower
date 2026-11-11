(function () {
  'use strict';
  if (window.watchtowerCandidatesInstalled) return;
  window.watchtowerCandidatesInstalled = true;
  var state = null, selected = null, run = null, offset = 0, preparation = null, reviewPage = 0, reviewGeneration = 0, reviewTimer, mutationInProgress = false, drafts = 0, step = 1;
  var STAGES = {DRAFT: 'Draft', SHADOW: 'In shadow', PROMOTED: 'Promoted', REJECTED: 'Rejected', ROLLED_BACK: 'Rolled back'};
  function dialog() { return document.querySelector('[data-rule-candidates-dialog]'); }
  function element(name) { return dialog().querySelector('[data-candidate-' + name + ']'); }
  function value(name) { return element(name).value; }
  function status(text) { element('status').textContent = text; }
  function words(code) { return STAGES[code] || code; }
  function make(tag, className, text) { var el = document.createElement(tag); if (className) el.className = className; if (text !== undefined) el.textContent = text; return el; }
  // A chip as the rest of the app draws it: icon, words, tone and the meaning on hover.
  function chip(label, icon, tone, tip) {
    var el = make('span', 'wt-mini-chip' + (tone ? ' wt-mini-chip--' + tone : ''));
    if (tip) { el.tabIndex = 0; el.setAttribute('data-tip', tip); }
    if (icon) { var i = make('span', 'material-icons', icon); i.setAttribute('aria-hidden', 'true'); el.appendChild(i); }
    el.appendChild(make('span', '', label));
    return el;
  }
  function tone(el, value) {
    ['ok', 'warn', 'bad'].forEach(function (t) { el.classList.toggle('wt-mini-chip--' + t, t === value); });
  }
  // Which fields differ from the live rule: a row says so (Changed, and the value it replaces), the footer counts them,
  // and Create draft only works when there is something to propose.
  function shorten(v) { var s = v === null ? 'no value' : typeof v === 'string' ? v : JSON.stringify(v); return s.length > 48 ? '…' + s.slice(-44) : s; }
  function changes() {
    var fields = element('fields'), count = 0;
    fields.querySelectorAll('[data-candidate-field]').forEach(function (input) {
      var field = input.dataset.candidateField, original = state.definition[field];
      var toggle = Array.from(fields.querySelectorAll('[data-candidate-null]')).find(function (t) { return t.dataset.candidateNull === field; });
      var next, valid = true;
      try { next = toggle && toggle.checked ? null : input.dataset.fieldType === 'string' ? input.value : JSON.parse(input.value); } catch (e) { valid = false; }
      var changed = !valid || JSON.stringify(original) !== JSON.stringify(next);
      if (changed) count++;
      var row = input.closest('[data-candidate-row]'), was = row.querySelector('[data-candidate-was]');
      row.classList.toggle('is-changed', changed);
      row.querySelector('[data-candidate-changed]').hidden = !changed;
      was.hidden = !changed;was.textContent = changed ? 'Was: ' + shorten(original) : '';
    });
    var stateChip = element('change-state');
    element('change-text').textContent = count ? count + (count === 1 ? ' change' : ' changes') : 'No changes yet';
    stateChip.querySelector('.material-icons').textContent = count ? 'check_circle' : 'edit_off';
    tone(stateChip, count ? 'ok' : '');
    element('create').disabled = !state || !state.authoringAvailable || !state.editableFields.length || !count;
  }
  // The 5-step bar (UAT walkthrough, 2026-10-16): one step's panel at a time, each step with its state.
  function steps() {
    var root = dialog();
    var states = {
      1: state && !state.authoringAvailable ? ['Not editable here', 'warn'] : ['Start here', ''],
      2: !preparation ? ['Checking…', ''] : preparation.suiteUsable ? ['Ready', 'ok'] : ['Needs setup', 'warn'],
      3: drafts ? [drafts + (drafts === 1 ? ' draft' : ' drafts'), ''] : ['No drafts', ''],
      4: selected && run ? ['Ready', 'ok'] : ['Locked', 'locked'],
      5: selected ? [words(selected.status), ''] : ['Locked', 'locked']
    };
    root.querySelectorAll('[data-candidate-step]').forEach(function (button) {
      var n = Number(button.dataset.candidateStep), entry = states[n];
      button.querySelector('[data-candidate-step-state]').textContent = entry[0];
      button.classList.toggle('is-warn', entry[1] === 'warn');
      button.classList.toggle('is-ok', entry[1] === 'ok');
      button.classList.toggle('is-locked', entry[1] === 'locked');
      button.classList.toggle('is-active', n === step);
      button.setAttribute('aria-selected', String(n === step));
    });
    root.querySelectorAll('[data-candidate-panel]').forEach(function (panel) { panel.hidden = Number(panel.dataset.candidatePanel) !== step; });
  }
  function show(n) { step = n; steps(); }
  function examples(fixtures) {
    var root = dialog();
    root.querySelectorAll('[data-candidate-cell]').forEach(function (cell) {
      var key = cell.dataset.candidateCell.split(':');
      var count = fixtures.filter(function (f) { return f.cohort === key[0] && f.expected_behavior === key[1]; }).length;
      cell.replaceChildren(count ? chip(count + (count === 1 ? ' example' : ' examples'), 'check', 'ok') : chip('None yet', 'close', 'bad'));
    });
    var list = element('fixtures');
    list.replaceChildren();
    fixtures.forEach(function (f) {
      var row = make('li', 'wt-meta-chips');
      row.appendChild(chip(f.cohort === 'HOLDOUT' ? 'Held-out' : 'Regression', 'folder', ''));
      row.appendChild(chip(f.expected_behavior === 'MATCH' ? 'Must match' : 'Must stay clean', f.expected_behavior === 'MATCH' ? 'bug_report' : 'verified', ''));
      row.appendChild(make('code', '', f.fixture_ref));
      row.appendChild(make('span', 'wt-muted', 'reviewed by ' + f.reviewer));
      list.appendChild(row);
    });
  }
  function history(entries) {
    var area = element('history');
    area.replaceChildren();
    entries.forEach(function (h) {
      area.appendChild(chip(String(h.revision || 'unknown').slice(0, 8), 'commit', '', h.revision || 'Revision not recorded'));
      area.appendChild(make('span', 'wt-muted', h.actor + ' · ' + (window.WatchtowerTime ? window.WatchtowerTime.format(h.created_at) : new Date(h.created_at).toLocaleString(undefined, {timeZoneName: 'short'}))));
    });
    if (!entries.length) area.appendChild(make('span', 'wt-muted', 'No recorded changes yet'));
  }
  async function api(path, method, data) {
    var options = {headers: {'Content-Type': 'application/json'}};
    if (method) {
      options.method = method;
      options.headers[dialog().dataset.csrfHeader] = dialog().dataset.csrfToken;
      if (data !== undefined) options.body = JSON.stringify(data);
    }
    var response = await fetch('/rule/candidates' + path, options);
    var body = await response.json();
    if (!response.ok) throw new Error(body.error || 'Candidate evidence unavailable. Reload after concurrent changes.');
    return body;
  }
  function actions() {
    var stages = {test: ['DRAFT', 'SHADOW'], shadow: ['DRAFT'], promote: ['SHADOW'], rollback: ['PROMOTED'], reject: ['DRAFT', 'SHADOW']};
    element('actions').querySelectorAll('[data-candidate-action]').forEach(function (button) {
      var name = button.dataset.candidateAction;
      button.disabled = !selected || !stages[name].includes(selected.status) ||
        (['test', 'shadow', 'promote'].includes(name) && (!state || !state.testingAvailable || !preparation || !preparation.suiteUsable)) ||
        (['shadow', 'promote'].includes(name) && !run);
      button.title = !selected ? 'Select a candidate first.' : button.disabled ? 'Check the candidate stage, fixture suite and required passing run.' : 'Review the exact revision before requesting this action.';
      // Actions that can't be used for this draft are hidden, not shown greyed out.
      button.hidden = !selected || !stages[name].includes(selected.status);
    });
    var decide = dialog().querySelector('[data-candidate-decide]'), none = dialog().querySelector('[data-candidate-decide-none]');
    if (decide) decide.hidden = !selected;
    if (none) none.hidden = !!selected;
    var shadowArea = dialog().querySelector('[data-candidate-shadow-area]'), locked = dialog().querySelector('[data-candidate-shadow-locked]');
    if (shadowArea) shadowArea.hidden = !selected;
    if (locked) locked.hidden = !!selected;
    if (element('stage')) element('stage').textContent = selected ? words(selected.status) + ' · ' + selected.revision.slice(0, 8) : '';
    if (element('prerequisites')) element('prerequisites').setAttribute('data-tip', 'Testing needs an enabled runner and usable reviewed examples. Shadow checks and promotion need a passing run of this exact revision. Review the exact evidence before promotion; rollback applies only while the promoted revision is active.');
    steps();
  }
  function evidence(row) {
    run = row.status === 'PASSED' ? row : null;
    element('approval').checked = false;
    var evidence;
    try { evidence = JSON.parse(row.evidence_json); } catch (_) { evidence = {}; }
    var lines = ['Test ' + row.run_id + ' · ' + row.status + ' · evidence ' + row.evidence_hash];
    if (evidence.executionIdentity) lines.push('Execution profile: ' + evidence.executionIdentity);
    if (evidence.limits) lines.push('Test limits: ' + JSON.stringify(evidence.limits));
    (evidence.fixtures || []).forEach(function (f) {
      lines.push(f.fixture.cohort + ' · ' + f.fixture.fixture_ref + ' · expected ' + f.fixture.expected_behavior +
        ' · active ' + f.base.status + '/' + f.base.matches.length + ' matches · candidate ' + f.candidate.status + '/' + f.candidate.matches.length +
        ' matches · ' + (f.expectationPassed ? 'expectation passed' : 'expectation failed'));
      [['Active', f.base], ['Candidate', f.candidate]].forEach(function (entry) {
        var result = entry[1];
        lines.push(entry[0] + ' · engine ' + result.engine + ' · errors ' + result.errors + ' · ' + result.elapsedMillis + ' ms');
        lines.push('Runtime: ' + result.runtime);lines.push(result.limitation);
        result.matches.forEach(function (m) { lines.push(entry[0] + ' match: ' + m.path + ':' + m.line + ' · message ' + m.messageKey); });
      });
      [['New matches', f.newlyMatched], ['New misses or changed messages', f.newlyMissed]].forEach(function (entry) {
        (entry[1] || []).forEach(function (m) { lines.push(entry[0] + ': ' + m.path + ':' + m.line + ' · message ' + m.messageKey); });
      });
    });
    element('results').textContent = lines.join('\n');actions();
  }
  async function choose(id) {
    selected = await api('/' + id);run = null;element('approval').checked = false;
    element('definition').textContent = 'Candidate ' + selected.candidate_id + '\nActive base: ' + selected.base_revision +
      '\nCandidate revision: ' + selected.revision + '\nStatus: ' + selected.status + '\n' +
      JSON.stringify(JSON.parse(selected.definition_json), null, 2);
    var rows = await api('/' + id + '/runs');element('runs').replaceChildren();element('results').textContent = '';
    rows.forEach(function (row) {
      var button = make('button', 'wt-mini-chip wt-mini-chip--link' + (row.status === 'PASSED' ? ' wt-mini-chip--ok' : row.status === 'FAILED' ? ' wt-mini-chip--bad' : ''));button.type = 'button';
      button.textContent = 'Test ' + row.status.toLowerCase() + ' · ' + (window.WatchtowerTime ? window.WatchtowerTime.format(row.created_at) : new Date(row.created_at).toLocaleString(undefined, {timeZoneName: 'short'}));
      button.addEventListener('click', function () { evidence(row); });element('runs').appendChild(button);
    });
    if (rows.length) evidence(rows[0]);await shadow();actions();
  }
  async function shadow() {
    if (!selected) return;
    try {
      var rows = await api('/' + selected.candidate_id + '/shadow?days=' + value('shadow-days'));
      var lines = ['At most 3 extra test requests per scan, sampling at most 20 files per candidate. These samples do not measure repository coverage.'];
      rows.forEach(function (row) {
        var e = JSON.parse(row.evidence_json);
        var pairs = e.comparisons && e.comparisons.cases || [];
        lines.push(row.scan_type + ' scan ' + row.scan_id + ' · ' + row.status + ' · ' + pairs.length + ' sampled files · ' + row.elapsed_millis + ' ms');
        pairs.forEach(function (pair) {
          var source = (e.files || []).find(function (f) { return f.id === pair.fixtureId; });
          lines.push((source ? source.path : pair.fixtureId) + ' · active ' + pair.base.status + '/' + pair.base.matches.length + ' matches · candidate ' + pair.candidate.status + '/' + pair.candidate.matches.length + ' matches');
        });
      });
      if (!rows.length) lines.push('No recorded shadow sample in this window.');
      element('shadow').textContent = lines.join('\n');
    } catch (error) { element('shadow').textContent = error.message; }
  }
  function candidates(rows) {
    element('list').replaceChildren();
    rows.forEach(function (row) {
      var button = make('button', 'wt-candidate-row');button.type = 'button';
      button.appendChild(chip(words(row.status), row.status === 'SHADOW' ? 'visibility' : 'edit_note', row.status === 'SHADOW' ? 'shadow' : ''));
      button.appendChild(make('code', '', row.revision.slice(0, 8)));
      button.appendChild(make('span', '', row.rationale));
      button.addEventListener('click', function () { choose(row.candidate_id).catch(function (e) { status(e.message); }); });element('list').appendChild(button);
    });
  }
  async function load() {
    var root = dialog(); state = null;preparation = null;element('create').disabled = true;element('fields').replaceChildren();status('Loading rule definition…');
    var loaded = await api('/workspace/' + root.dataset.ruleId);if (root !== dialog()) return; state = loaded; selected = null;run = null;offset = 0;
    if (!state || !state.definition || !Array.isArray(state.editableFields) || !state.fieldMetadata ||
        state.editableFields.some(field => !Object.prototype.hasOwnProperty.call(state.definition, field) || !state.fieldMetadata[field])) {
      state = null;throw new Error('The rule definition could not load. Reload the page to retry.');
    }
    // R3 is bounded direct engine execution, never a sandbox; the chip says so either way.
    var availability = element('availability');
    tone(availability, state.testingAvailable ? 'warn' : 'bad');
    element('availability-text').textContent = state.testingAvailable ? 'Not sandboxed' : 'Test runner off';
    availability.setAttribute('data-tip', state.testingAvailable
      ? 'Draft tests run the real engine with time and size limits, but not in a sandbox. Live scanning keeps using the current rule while a draft is tested. Expectations come from reviewed, secret-free examples.'
      : 'The test runner is turned off or unavailable, so drafts can be written but not tested, shadow-checked or promoted.');
    element('fields').replaceChildren();
    var labels = {regexPattern: 'Matching pattern', fileExtension: 'File extension', query: 'JSONPath query', message: 'Finding message', properties: 'PMD properties',
      createFunction: 'ESLint create function', schema: 'ESLint schema', messages: 'ESLint messages', regex: 'Matching pattern', keywords: 'Keywords', entropy: 'Entropy', secretGroup: 'Secret group', filter: 'Filter'};
    state.editableFields.forEach(function (field) {
      // One row per field: label, input, and on the right "No value" plus a Changed chip.
      var row = make('div', 'wt-candidate-field');row.dataset.candidateRow = field;
      var aside = make('div', 'wt-candidate-field__aside');
      var label = document.createElement('label');label.className = 'wt-label wt-candidate-field__label';label.appendChild(make('span', '', labels[field] || field));
      var was = make('small', 'wt-candidate-field__was');was.dataset.candidateWas = '';was.hidden = true;label.appendChild(was);
      var changedChip = chip('Changed', 'edit', '');changedChip.dataset.candidateChanged = '';changedChip.hidden = true;aside.appendChild(changedChip);
      var input = document.createElement('textarea');input.className = 'form-control wt-candidate-field__input';input.rows = 1;input.dataset.candidateField = field;
      input.id = 'candidate-field-' + field;label.htmlFor = input.id;
      input.dataset.fieldType = state.fieldMetadata[field].type;
      if (input.dataset.fieldType !== 'string' || /function|schema|properties|messages/i.test(field)) input.classList.add('wt-candidate-field__code');
      input.value = state.definition[field] === null ? 'null' : typeof state.definition[field] === 'string' ? state.definition[field] : JSON.stringify(state.definition[field]);
      if (state.fieldMetadata[field].nullable) {
        var nullLabel = document.createElement('label');nullLabel.className = 'wt-checkbox-label';
        var nullToggle = document.createElement('input');nullToggle.type = 'checkbox';nullToggle.dataset.candidateNull = field;
        nullToggle.checked = state.definition[field] === null;input.disabled = nullToggle.checked;
        nullToggle.addEventListener('change', function () { input.disabled = nullToggle.checked; if (!nullToggle.checked && input.value === 'null') input.value = input.dataset.fieldType === 'string' ? '' : input.dataset.fieldType === 'array' ? '[]' : input.dataset.fieldType === 'object' ? '{}' : '0'; });
        nullLabel.append(nullToggle, document.createTextNode('No value'));aside.appendChild(nullLabel);
      }
      row.append(label, input, aside);element('fields').appendChild(row);
    });
    var fieldsHost = element('fields');
    if (!fieldsHost.dataset.wired) { fieldsHost.dataset.wired = 'true';fieldsHost.addEventListener('input', changes);fieldsHost.addEventListener('change', changes); }
    var why = element('rationale');
    if (!why.dataset.wired) { why.dataset.wired = 'true';why.addEventListener('input', function () { element('rationale-count').textContent = why.value.length + ' / 300'; }); }
    changes();
    var authoring = element('authoring');
    authoring.hidden = state.authoringAvailable;
    element('authoring-links').hidden = state.authoringAvailable;
    authoring.setAttribute('data-tip', (state.authoringReasons || ['Authoring is unavailable.']).join(' '));
    status('');await candidatePage();
    element('definition').textContent = '';element('results').textContent = '';element('shadow').textContent = '';element('runs').replaceChildren();element('approval').checked = false;
    examples(state.fixtures);
    history(state.history);
    preparation = await api('/rule/' + state.ruleId + '/preparation');
    var ready = element('preparation');
    tone(ready, preparation.suiteUsable ? 'ok' : 'warn');
    ready.querySelector('.material-icons').textContent = preparation.suiteUsable ? 'check_circle' : 'folder_off';
    element('preparation-text').textContent = preparation.suiteUsable ? 'Ready to test' : 'Needs setup';
    ready.setAttribute('data-tip', preparation.suiteUsable ? 'The reviewed examples are usable: files and hashes were checked. Tests still only run when you start them.' : preparation.reasons.join(' '));
    if (element('review-search')) { reviewPage = 0; await reviewChoices(); }
    actions();
    var requested = new URLSearchParams(location.search).get('candidate');
    if (requested) { await choose(requested); show(2); }
  }
  async function candidatePage() {
    var page = await api('/rule/' + state.ruleId + '/page?page=' + offset);
    candidates(page.content);element('previous').disabled = offset === 0;element('next').disabled = offset + 1 >= page.totalPages;
    drafts = page.totalElements;
    element('compare').hidden = !drafts;element('none').hidden = !!drafts;
    element('previous').hidden = element('next').hidden = page.totalPages <= 1;
    if (element('page-status')) element('page-status').textContent = drafts ? drafts + (drafts === 1 ? ' draft' : ' drafts') + (page.totalPages > 1 ? ' · page ' + (offset + 1) + ' of ' + page.totalPages : '') : '';
    steps();
  }
  async function reviewChoices() {
    var generation = ++reviewGeneration, root = dialog();
    var params = new URLSearchParams({revision: state.revision || 'unknown', search: value('review-search'), page: reviewPage});
    var response = await fetch('/rules/' + state.ruleId + '/reviews/options?' + params);
    if (!response.ok) throw new Error('Review choices could not load (' + response.status + '). Reload or retry.');
    var page = await response.json();if (generation !== reviewGeneration || root !== dialog()) return;
    var select = element('review'), chosen = select.selectedOptions[0], current = select.value;
    select.replaceChildren(new Option('No attached review', ''));
    if (current && !page.content.some(r => r.id === current)) select.appendChild(chosen);
    page.content.forEach(function (review) { var option = document.createElement('option'); option.value = review.id; option.textContent = review.status + ' · ' + review.owner + ' · ' + review.reason; option.dataset.preview = review.recommendation; select.appendChild(option); });
    select.value = current;
    element('review-previous').disabled = reviewPage === 0;element('review-next').disabled = reviewPage + 1 >= page.totalPages;
    element('review-page-status').textContent = page.totalElements ? page.totalElements + ' open reviews for this revision' : 'No open review matches this revision and search. A review attachment is optional.';
  }
  function initialize() {
    var root = document.querySelector('[data-rule-candidates-page]');if (!root || root.dataset.ready) return;root.dataset.ready = 'true';
    step = Number(root.dataset.startStep || 1);steps();
    load().catch(function (error) { if (root === dialog()) status(error.message); });
  }
  document.addEventListener('DOMContentLoaded', initialize);document.addEventListener('htmx:afterSwap', initialize);
  document.addEventListener('click', async function (event) {
    if (!dialog()) return;
    var mutating = !!event.target.closest('[data-candidate-create],[data-candidate-fixture-save],[data-candidate-case-register],[data-candidate-action]');
    if (mutating && mutationInProgress) return;
    if (mutating) mutationInProgress = true;
    try {
      var stepButton = event.target.closest('[data-candidate-step]');
      if (stepButton) show(Number(stepButton.dataset.candidateStep));
      if (event.target.closest('[data-rule-candidates-open]')) { state = null;element('create').disabled = true;await dialog().show();await load(); }
      if (event.target.closest('[data-rule-candidates-close]')) dialog().close();
      if (event.target.closest('[data-candidate-reload]')) await load();
      if (event.target.closest('[data-candidate-review-previous],[data-candidate-review-next]')) {
        reviewPage = event.target.closest('[data-candidate-review-next]') ? reviewPage + 1 : Math.max(0, reviewPage - 1);await reviewChoices();
      }
      if (event.target.closest('[data-candidate-case-register]')) {
        if (!state) throw new Error('Load the rule workspace first.');
        var example = dialog().querySelector('[data-candidate-case]');
        if (!element('case-confirm').checked) throw new Error('Confirm the saved expectation and selected collection first.');
        await api('/fixtures/from-case','POST',{ruleId:state.ruleId,baseRevision:state.revision,caseId:example.dataset.caseId,expected:value('case-expected'),cohort:value('case-cohort'),confirmed:true});
        element('case-confirm').checked=false;await load();status('Verified example registered as an executable fixture. Tests have not run.');
      }
      if (event.target.closest('[data-candidate-create]')) {
        if (!state || !state.authoringAvailable || element('create').disabled) throw new Error('Load a valid, supported rule definition before creating a draft.');
        var changes = {};
        element('fields').querySelectorAll('[data-candidate-field]').forEach(function (input) {
          var field = input.dataset.candidateField, original = state.definition[field];
          var nullToggle = Array.from(element('fields').querySelectorAll('[data-candidate-null]')).find(toggle => toggle.dataset.candidateNull === field);
          var next = nullToggle && nullToggle.checked ? null : input.dataset.fieldType === 'string' ? input.value : JSON.parse(input.value);
          var kind = next === null ? 'null' : Array.isArray(next) ? 'array' : typeof next;
          if (kind !== 'null' && kind !== input.dataset.fieldType) throw new Error('Check the ' + field + ' value; expected ' + input.dataset.fieldType + '.');
          if (JSON.stringify(original) !== JSON.stringify(next)) changes[field] = next;
        });
        var draft = await api('', 'POST', {ruleId: state.ruleId, baseRevision: state.revision, changes: changes, rationale: value('rationale'), reviewId: value('review') || null});
        offset = 0;await candidatePage();await choose(draft.id);show(2);status('Draft saved. The live rule keeps running; add examples, then compare.');
      }
      if (event.target.closest('[data-candidate-fixture-save]')) {
        await api('/fixtures', 'POST', {ruleId: state.ruleId, reference: value('fixture-reference'), sha256: value('fixture-hash'),
          expected: value('fixture-expected'), cohort: value('fixture-cohort'), evidenceReference: value('fixture-evidence')});
        var exampleDialog = event.target.closest('md-dialog');
        if (exampleDialog && typeof exampleDialog.close === 'function') exampleDialog.close();
        await load();status('Example saved. Tests have not run.');
      }
      if (event.target.closest('[data-candidate-previous],[data-candidate-next]')) {
        offset = event.target.closest('[data-candidate-next]') ? offset + 1 : Math.max(0, offset - 1);
        await candidatePage();
      }
      var button = event.target.closest('[data-candidate-action]');
      if (button && !button.disabled && selected) {
        var action = button.dataset.candidateAction;
        if (action === 'test') {
          var queued = await api('/' + selected.candidate_id + '/test', 'POST');
          status('Test queued: ' + queued.runId + '. Reopen the candidate to view its result.');
        } else {
          if (!element('approval').checked) throw new Error('Review the exact displayed candidate and evidence, then check the approval box.');
          var id = selected.candidate_id;
          await api('/' + id + '/' + action, 'POST', {version: selected.version, revision: selected.revision,
            runId: run ? run.run_id : null, evidenceHash: run ? run.evidence_hash : null, rationale: value('rationale')});
          await load();await choose(id);status('Review action saved. Reload the rule editor after promotion or rollback.');
        }
      }
    } catch (error) { status(error.message); }
    finally { if (mutating) mutationInProgress = false; }
  });
  document.addEventListener('change', function (event) {
    if (dialog() && event.target.matches('[data-candidate-shadow-days]')) shadow();
    if (dialog() && event.target.matches('[data-candidate-review]')) element('review-preview').textContent = event.target.selectedOptions[0].dataset.preview || '';
  });
  document.addEventListener('input', function (event) { if (dialog() && event.target.matches('[data-candidate-review-search]')) { clearTimeout(reviewTimer);reviewTimer = setTimeout(function () { reviewPage = 0;reviewChoices().catch(e => status(e.message)); },200); } });
  initialize();
})();

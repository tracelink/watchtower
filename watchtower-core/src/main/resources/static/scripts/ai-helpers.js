(function () {
 'use strict';
 // AI helpers beside existing pages (helpers board, approved 2026-10-24): share my draft with the
 // assistant, a summary for a bypass request, a diagnosis for a failed job, and triage dots on a scan's
 // findings. Each shows only when the server says it will work for this person. They advise; none of
 // them records a judgment or changes anything. All text is set with textContent.
 var MAX_POLLS = 400, MAX_DRAFT_FIELDS = 40;
 var settings = {pollMs: 3000};
 var flagsPromise = null;
 function drawer() { return document.querySelector('wt-assistant-drawer'); }
 async function api(path, method, body) {
  var d = drawer(), headers = {Accept: 'application/json'};
  if (method === 'POST') { headers['Content-Type'] = 'application/json'; if (d) headers[d.dataset.csrfHeader] = d.dataset.csrfToken; }
  var response = await fetch(path, {method: method || 'GET', headers: headers, body: body === undefined ? undefined : JSON.stringify(body)});
  var data = {}; try { data = await response.json(); } catch (e) { data = {}; }
  if (!response.ok) { var error = new Error(data.error || data.message || ('This is unavailable right now (' + response.status + ').')); error.status = response.status; throw error; }
  return data;
 }
 function helperFlags() { if (!flagsPromise) flagsPromise = api('/assistant/helpers').catch(function () { return {}; }); return flagsPromise; }
 function text(parent, tag, value, className) { var el = document.createElement(tag); el.textContent = value; if (className) el.className = className; parent.appendChild(el); return el; }
 function icon(parent, name) { var el = text(parent, 'span', name, 'material-icons'); el.setAttribute('aria-hidden', 'true'); return el; }
 function chip(parent, iconName, label, tone, tip) {
  var el = document.createElement('span'); el.className = 'wt-mini-chip' + (tone ? ' wt-mini-chip--' + tone : '');
  if (iconName) icon(el, iconName); el.appendChild(document.createTextNode(label));
  if (tip) { el.setAttribute('data-tip', tip); el.tabIndex = 0; }
  parent.appendChild(el); return el;
 }
 function setTip(el, tip) { el.setAttribute('data-tip', tip); }

 /** The text of the designer being typed in, as "label: value" lines; the server checks it before it is sent on. */
 function collectDraft() {
  var scope = document.querySelector('[data-ai-draft-scope]'); if (!scope) return '';
  var fields = scope.querySelectorAll('textarea, input:not([type=hidden]):not([type=password]):not([type=checkbox]):not([type=radio]):not([type=file]):not([type=submit]), md-outlined-text-field, md-filled-text-field');
  var lines = [];
  Array.prototype.slice.call(fields, 0, MAX_DRAFT_FIELDS).forEach(function (field) {
   var value = String(field.value == null ? '' : field.value).trim(); if (!value) return;
   var label = field.getAttribute('label') || field.getAttribute('aria-label') || field.name || field.id || 'field';
   lines.push(label + ': ' + value);
  });
  return lines.join('\n');
 }

 function bindDraft(button) {
  button.addEventListener('click', function () {
   var on = button.getAttribute('aria-pressed') !== 'true';
   button.setAttribute('aria-pressed', String(on));
   document.dispatchEvent(new CustomEvent('wt:assistant-draft', {detail: {on: on}}));
   var d = drawer(); if (on && d && d.panel && d.panel.hidden) d.open(undefined, undefined, button);
  });
  document.addEventListener('wt:assistant-draft-cleared', function () { button.setAttribute('aria-pressed', 'false'); });
 }

 var REASONS = {FALSE_POSITIVE: 'a false positive', ACCEPTED_RISK: 'an accepted risk', TEST_CODE: 'test code', NOT_EXPLOITABLE: 'not exploitable', OTHER: 'another reason'};
 function renderBypass(panel, button, summary) {
  panel.replaceChildren();
  if (summary.state === 'BLOCKED') {
   button.classList.add('wt-mini-chip--bad'); button.querySelector('.material-icons').textContent = 'lock';
   button.querySelector('[data-ai-bypass-label]').textContent = 'No AI summary'; setTip(button, summary.message);
   panel.hidden = true; return;
  }
  if (summary.state !== 'OK') { text(panel, 'p', summary.message || 'No summary is available.', 'wt-field-help'); panel.hidden = false; return; }
  text(panel, 'span', 'AI summary · advice, not a decision', 'wt-ai-summary__title');
  var row = text(panel, 'div', '', 'wt-meta-chips');
  chip(row, 'help_outline', 'Asks to bypass ' + summary.total + (summary.total === 1 ? ' finding' : ' findings') + ' as ' + (REASONS[summary.reason_code] || 'another reason'), '', 'What the request asks for, from its reason code.');
  var counts = Object.keys(summary.by_severity || {}).map(function (k) { return summary.by_severity[k] + ' ' + k.toLowerCase().replace(/_/g, ' '); }).join(', ');
  chip(row, 'description', summary.files + (summary.files === 1 ? ' file' : ' files') + ' · ' + counts, '', 'Blocking findings by severity: ' + counts + '.');
  if (summary.risk_note) chip(row, summary.attention === 'HIGH' ? 'priority_high' : 'info', 'Risk note', summary.attention === 'HIGH' ? 'warn' : '', summary.risk_note);
  else chip(row, 'info', 'No risk note', '', 'The assistant did not produce a usable note. The counts come from the scan.');
  panel.hidden = false;
 }
 function bindBypass(button) {
  var panel = button.parentElement.querySelector('[data-ai-bypass-panel]'), loaded = false, busy = false;
  button.addEventListener('click', async function () {
   if (loaded) { panel.hidden = !panel.hidden; return; }
   if (busy) return; busy = true; button.setAttribute('aria-busy', 'true');
   try { renderBypass(panel, button, await api('/assistant/bypass-summary/' + encodeURIComponent(button.dataset.requestId), 'POST')); loaded = true; }
   catch (e) { panel.replaceChildren(); text(panel, 'p', e.message, 'wt-field-help'); panel.hidden = false; }
   finally { busy = false; button.removeAttribute('aria-busy'); }
  });
 }

 function closeDiagnoses() { document.querySelectorAll('[data-ai-diagnosis]').forEach(function (card) { card.remove(); }); }
 function diagnosisCard(cell) { var card = document.createElement('div'); card.className = 'wt-ai-diagnosis'; card.setAttribute('data-ai-diagnosis', ''); card.setAttribute('role', 'dialog'); card.setAttribute('aria-label', 'AI diagnosis'); cell.appendChild(card); return card; }
 function renderDiagnosis(cell, result) {
  var card = diagnosisCard(cell);
  if (result.state !== 'OK') { text(card, 'p', result.message || 'The assistant could not explain this one.', 'wt-field-help'); return; }
  var head = text(card, 'div', '', 'wt-ai-diagnosis__head'); icon(head, 'auto_awesome').classList.add('wt-ai-icon'); text(head, 'strong', 'Likely cause');
  chip(head, 'lightbulb', 'Suggestion only', 'info', 'The assistant suggests; you decide what to do.');
  text(card, 'p', result.likely_cause);
  var next = text(card, 'div', '', 'wt-ai-diagnosis__head'); icon(next, 'arrow_forward'); text(next, 'strong', 'Next step');
  text(card, 'p', result.next_step);
  var foot = text(card, 'div', '', 'wt-meta-chips');
  if (result.fix_page && /^\/[A-Za-z0-9/_-]*$/.test(result.fix_page)) {
   var link = document.createElement('a'); link.href = result.fix_page; link.className = 'wt-mini-chip wt-mini-chip--link';
   icon(link, 'settings_ethernet'); link.appendChild(document.createTextNode('Open the page that fixes it')); foot.appendChild(link);
  }
  chip(foot, 'visibility_off', 'No code or secrets were sent', '', 'Only the job type, its status and a cleaned-up error message were sent.');
 }
 function bindDiagnose(button) {
  var cell = button.parentElement, busy = false;
  button.addEventListener('click', async function (event) {
   event.stopPropagation();
   var open = cell.querySelector('[data-ai-diagnosis]'); closeDiagnoses(); if (open) return;
   if (busy) return; busy = true; button.setAttribute('aria-busy', 'true');
   try { renderDiagnosis(cell, await api('/assistant/diagnose-job/' + encodeURIComponent(button.dataset.jobId), 'POST')); }
   catch (e) { text(diagnosisCard(cell), 'p', e.message, 'wt-field-help'); }
   finally { busy = false; button.removeAttribute('aria-busy'); }
  });
 }
 document.addEventListener('click', function (event) { if (!event.target.closest('[data-ai-diagnosis], [data-ai-helper="diagnose"]')) closeDiagnoses(); });

 // Suggest a ruleset (repository page): one recommendation with a link to the review page. Nothing is assigned here.
 function closeSuggestions() { document.querySelectorAll('[data-ai-suggestion]').forEach(function (card) { card.remove(); }); }
 function suggestionCard(anchor) {
  var card = document.createElement('div'); card.className = 'wt-ai-diagnosis'; card.setAttribute('data-ai-suggestion', ''); card.setAttribute('role', 'dialog'); card.setAttribute('aria-label', 'Suggested ruleset');
  anchor.appendChild(card); return card;
 }
 function renderSuggestion(anchor, result) {
  var card = suggestionCard(anchor);
  if (result.state === 'ACTIONS_OFF') {
   chip(text(card, 'div', '', 'wt-meta-chips'), 'lock', 'Ruleset actions are off', 'bad', 'Preparing a change needs Ruleset actions.');
   text(card, 'p', result.message); return;
  }
  var head = text(card, 'div', '', 'wt-ai-diagnosis__head'); icon(head, 'auto_awesome').classList.add('wt-ai-icon'); text(head, 'strong', 'Suggested ruleset');
  chip(head, 'lightbulb', 'Suggestion only', 'info', 'The assistant suggests; you decide what to do.');
  if (!result.ruleset) { text(card, 'p', result.message || 'No suggestion is available.', 'wt-field-help'); return; }
  var row = text(card, 'div', '', 'wt-meta-chips');
  if (result.state === 'FITS') chip(row, 'check_circle', 'Already uses ' + result.ruleset.name, 'ok', 'This is the ruleset the assistant would pick, so there is nothing to change.');
  else chip(row, 'rule', result.ruleset.name, 'link', 'The recommended ruleset.');
  if (result.language) chip(row, 'code', result.language, '', 'The repository language.');
  if (result.state !== 'FITS') chip(row, result.current ? 'swap_horiz' : 'block', result.current ? 'Today: ' + result.current.name : 'No ruleset today', '', result.current ? 'The ruleset this repository uses now.' : 'This repository has no ruleset assigned.');
  if (result.peers && result.peers.total > 0) chip(row, 'groups', result.peers.using + ' of ' + result.peers.total + (result.language ? ' ' + result.language : '') + ' repos', '', 'Other repositories of this language that use this ruleset, counted from the repository list.');
  if (result.reason) text(card, 'p', result.reason);
  if (result.state === 'OK' && /^\/assistant\/change-sets\/[A-Za-z0-9-]+\/review$/.test(result.reviewUrl || '')) {
   var foot = text(card, 'div', '', 'wt-meta-chips');
   var link = document.createElement('a'); link.href = result.reviewUrl; link.className = 'btn btn-primary btn-sm';
   icon(link, 'fact_check'); link.appendChild(document.createTextNode('Review change set')); foot.appendChild(link);
   chip(foot, 'how_to_reg', 'Needs your approval', 'warn', 'Nothing changes until you press Approve and apply on the review page. The draft expires in 30 minutes.');
  }
  chip(text(card, 'div', '', 'wt-meta-chips'), 'visibility_off', 'No code was sent', '', 'Only the language and ruleset names were sent.');
 }
 function bindOnboarding(anchor) {
  var button = anchor.querySelector('button'), busy = false, last = null;
  button.addEventListener('click', async function (event) {
   event.stopPropagation();
   var open = anchor.querySelector('[data-ai-suggestion]'); closeSuggestions(); button.setAttribute('aria-expanded', 'false'); if (open) return;
   // Each suggestion prepares a draft, so one is shown again until its draft expires instead of asking again.
   if (last && (!last.expiresAt || last.expiresAt > Date.now() + 60000)) { renderSuggestion(anchor, last); button.setAttribute('aria-expanded', 'true'); return; }
   if (busy) return; busy = true; button.setAttribute('aria-busy', 'true'); button.setAttribute('aria-expanded', 'true');
   try { var answer = await api('/assistant/onboarding/' + encodeURIComponent(button.dataset.repoId), 'POST'); last = answer.state === 'OK' || answer.state === 'FITS' ? answer : null; renderSuggestion(anchor, answer); }
   catch (e) { text(suggestionCard(anchor), 'p', e.message, 'wt-field-help'); }
   finally { busy = false; button.removeAttribute('aria-busy'); }
  });
  document.addEventListener('click', function (event) {
   if (event.target.closest('[data-ai-suggestion], [data-ai-helper="onboarding"]')) return;
   closeSuggestions(); button.setAttribute('aria-expanded', 'false');
  });
 }

 // Draft fixture (Find similar code, step 1): a small example of the miss, shown here and kept nowhere.
 function renderFixture(area, result) {
  area.replaceChildren();
  if (result.state === 'BLOCKED') {
   var blocked = text(area, 'div', '', 'wt-ai-fixture wt-ai-fixture--blocked'); icon(blocked, 'lock'); text(blocked, 'span', result.message); return;
  }
  if (result.state !== 'OK') { text(area, 'p', result.message || 'No example is available.', 'wt-field-help'); return; }
  var box = text(area, 'div', '', 'wt-ai-fixture');
  var row = text(box, 'div', '', 'wt-meta-chips');
  chip(row, 'edit_note', 'Draft only · not saved', 'info', 'Nothing is stored. Copy it if you want to keep it.');
  chip(row, 'add_circle', 'Should match', 'ok', 'A rule for this weakness should flag this example.');
  chip(row, 'visibility_off', 'Secrets are never sent', '', 'Lines near a recorded secret are never sent, and then no example is drafted.');
  var copy = document.createElement('button'); copy.type = 'button'; copy.className = 'wt-icon-action'; copy.setAttribute('aria-label', 'Copy the example'); setTip(copy, 'Copy the example');
  icon(copy, 'content_copy'); row.appendChild(copy);
  copy.addEventListener('click', function () {
   function failed() { setTip(copy, 'Copy is not available here'); }
   try { navigator.clipboard.writeText(result.example).then(function () { setTip(copy, 'Copied'); }, failed); } catch (e) { failed(); }
  });
  var code = text(box, 'pre', result.example, 'wt-variant-excerpt');
  code.tabIndex = 0;
  text(box, 'p', (result.note ? result.note + ' ' : '') + 'Check it against your rule before you keep it.', 'wt-field-help');
 }
 function bindFixture(button) {
  var dialog = button.closest('[data-variant-dialog]'), area = dialog && dialog.querySelector('[data-ai-fixture-result]'), busy = false;
  if (!area) { button.remove(); return; }
  button.addEventListener('click', async function () {
   var caseId = dialog.dataset.caseId;
   if (busy || !caseId) return; busy = true; button.setAttribute('aria-busy', 'true'); button.disabled = true;
   area.replaceChildren(); text(area, 'p', 'Drafting an example…', 'wt-field-help');
   // An answer for a case that is no longer open is dropped, so it never shows under another case.
   function current() { return dialog.dataset.caseId === caseId; }
   try { var result = await api('/assistant/draft-fixture/' + encodeURIComponent(caseId), 'POST'); if (current()) renderFixture(area, result); }
   catch (e) { if (current()) { area.replaceChildren(); text(area, 'p', e.message, 'wt-field-help'); } }
   finally { busy = false; button.disabled = false; button.removeAttribute('aria-busy'); }
  });
 }

 // Alert routes: how a route reads in chips, shared by the draft dialog and the review page.
 var PRIORITY = {HIGH: 'High', MEDIUM_HIGH: 'Medium high', MEDIUM: 'Medium', MEDIUM_LOW: 'Medium low', LOW: 'Low', INFORMATIONAL: 'Informational'};
 function alertName(key) { var t = String(key || '').replace(/_/g, ' ').toLowerCase().replace(/\bpr\b/g, 'PR'); return t.charAt(0).toUpperCase() + t.slice(1); }
 function alertIcon(key) { var k = String(key || '').toLowerCase(); return k.indexOf('secret') >= 0 ? 'key' : k.indexOf('fail') >= 0 ? 'error_outline' : 'notifications'; }
 function windowText(hours) { return hours >= 24 && hours % 24 === 0 ? (hours / 24) + (hours === 24 ? ' day' : ' days') : hours + (hours === 1 ? ' hour' : ' hours'); }
 /** The settings of a route as short phrases; the same phrases on both sides of a change show what moved. */
 function settingPhrases(route) {
  var out = {};
  out.aggregation = route.aggregation === 'PER_FINDING' ? '1 per finding' : '1 per scan';
  out.hours = 'No repeats for ' + windowText(route.dedupeWindowHours);
  if (route.minPriority) out.priority = (PRIORITY[route.minPriority] || route.minPriority) + ' and above';
  if (route.apiLabelFilter) out.label = 'Only ' + route.apiLabelFilter;
  if (route.repoInclude) out.include = 'Only: ' + route.repoInclude;
  if (route.repoExclude) out.exclude = 'Except: ' + route.repoExclude;
  return out;
 }
 function routeLine(parent, route) {
  var row = text(parent, 'span', '', 'wt-route-summary');
  chip(row, alertIcon(route.alertType), alertName(route.alertType), /secret/i.test(route.alertType) ? 'bad' : '', null);
  icon(row, 'arrow_forward').classList.add('wt-tone-neutral');
  chip(row, 'forum', route.channelName, '', route.channelEnabled === false ? 'This channel is turned off.' : null);
  return row;
 }
 /** Chips for one side of a change; a setting that differs from the other side is highlighted. */
 function settingChips(parent, route, other, tone) {
  var mine = settingPhrases(route), theirs = other ? settingPhrases(other) : {};
  if (other && route.channelName !== other.channelName) chip(parent, 'forum', route.channelName, tone, 'The channel.');
  Object.keys(mine).forEach(function (key) { chip(parent, '', mine[key], other && mine[key] !== theirs[key] ? tone : '', null); });
 }
 /** Only what changed, as before → after chips; used in the small list in the draft dialog. */
 function changedChips(parent, before, after) {
  var a = settingPhrases(before), b = settingPhrases(after);
  if (before.channelName !== after.channelName) { chip(parent, 'forum', before.channelName, 'warn', null); icon(parent, 'arrow_forward'); chip(parent, 'forum', after.channelName, 'ok', null); }
  ['aggregation', 'hours', 'priority', 'label', 'include', 'exclude'].forEach(function (key) {
   if (a[key] === b[key]) return;
   if (a[key]) chip(parent, '', a[key], 'warn', null); else chip(parent, '', 'No filter', 'warn', null);
   icon(parent, 'arrow_forward');
   if (b[key]) chip(parent, '', b[key], 'ok', null); else chip(parent, '', 'No filter', 'ok', null);
  });
 }
 var KIND = {ADD: ['add', 'Add', 'ok'], UPDATE: ['edit', 'Change', 'warn'], REMOVE: ['delete', 'Remove', 'bad']};
 function kindChip(parent, type) { var k = KIND[type] || ['help', type, '']; return chip(parent, k[0], k[1], k[2], null); }
 function note(parent, iconName, tone, message) {
  var box = text(parent, 'div', '', 'wt-ai-note wt-ai-note--' + tone); icon(box, iconName); text(box, 'span', message); return box;
 }
 var REVIEW_URL = /^\/assistant\/alert-changes\/[A-Za-z0-9-]+\/review$/;

 // Draft route changes (Alert settings): a sentence in, a reviewable draft out. Nothing is applied here.
 function renderAlertDraft(parts, result) {
  parts.result.replaceChildren();
  if (result.state !== 'OK') {
   var tone = result.state === 'REFUSED_SECRET' ? 'bad' : result.state === 'NOTHING' ? 'info' : 'warn';
   note(parts.result, result.state === 'REFUSED_SECRET' ? 'lock' : result.state === 'NOTHING' ? 'check_circle' : 'info', tone, result.message || 'The assistant could not draft that.');
   return;
  }
  var changes = result.changes || [];
  var head = text(parts.result, 'div', '', 'wt-meta-chips');
  text(head, 'strong', changes.length + (changes.length === 1 ? ' change drafted' : ' changes drafted'));
  chip(head, 'forum', 'Channels are never changed', '', 'Only routes are drafted. Channels and their webhook addresses are managed on the Channels tab.');
  if (result.dropped) chip(head, 'info', result.dropped + ' left out', 'warn', 'Part of the answer repeated a route or changed nothing, so it was left out.');
  changes.forEach(function (change) {
   var row = text(parts.result, 'div', '', 'wt-ai-change');
   kindChip(row, change.type);
   routeLine(row, change.after || change.before);
   if (change.type === 'UPDATE') changedChips(row, change.before, change.after);
   else if (change.type === 'ADD') settingChips(row, change.after, null, '');
  });
  if (REVIEW_URL.test(result.reviewUrl || '')) { parts.review.href = result.reviewUrl; parts.review.hidden = false; parts.approval.hidden = false; parts.draft.hidden = true; }
 }
 function bindAlerts(anchor) {
  var button = anchor.querySelector('button'), dialog = document.getElementById('alertCopilotDialog');
  if (!dialog) { anchor.remove(); return; }
  var parts = {
   field: dialog.querySelector('[data-alert-copilot-text]'), result: dialog.querySelector('[data-alert-copilot-result]'), draft: dialog.querySelector('[data-alert-copilot-draft]'),
   review: dialog.querySelector('[data-alert-copilot-review]'), approval: dialog.querySelector('[data-alert-copilot-approval]')
  }, busy = false;
  function reset() { parts.result.replaceChildren(); parts.review.hidden = true; parts.approval.hidden = true; parts.draft.hidden = false; parts.draft.disabled = false; }
  button.addEventListener('click', function () { reset(); parts.field.value = ''; dialog.show(); });
  Array.prototype.forEach.call(dialog.querySelectorAll('[data-alert-copilot-close]'), function (el) { el.addEventListener('click', function () { dialog.close(); }); });
  Array.prototype.forEach.call(dialog.querySelectorAll('[data-alert-copilot-example]'), function (el) {
   el.addEventListener('click', function () { reset(); parts.field.value = el.dataset.text; });
  });
  // Changing the sentence after a draft makes the old draft stale, so the button to ask again comes back.
  parts.field.addEventListener('input', function () { if (parts.review.hidden === false) reset(); });
  parts.draft.addEventListener('click', async function () {
   if (busy) return;
   var sentence = String(parts.field.value || '').trim();
   if (!sentence) { parts.result.replaceChildren(); note(parts.result, 'info', 'info', 'Describe the change in your own words first.'); return; }
   busy = true; parts.draft.disabled = true; parts.result.replaceChildren(); text(parts.result, 'p', 'Drafting…', 'wt-field-help');
   try { renderAlertDraft(parts, await api('/assistant/alert-copilot', 'POST', {text: sentence})); }
   catch (e) { parts.result.replaceChildren(); note(parts.result, e.status === 429 ? 'hourglass_empty' : 'info', 'warn', e.message); }
   finally { busy = false; parts.draft.disabled = false; }
  });
 }

 var DOTS = {
  LIKELY_TRUE_POSITIVE: ['help', 'bad', 'AI advice: likely true positive. Not a verdict; you decide.'],
  LIKELY_FALSE_POSITIVE: ['check_circle', 'ok', 'AI advice: likely false positive. Not a verdict; you decide.'],
  NEEDS_REVIEW: ['contact_support', 'warn', 'AI advice: needs review. Not a verdict; you decide.'],
  INSUFFICIENT_EVIDENCE: ['help_outline', 'none', 'AI advice: there was not enough evidence to say.']
 };
 function dotFor(item) {
  if (item.status === 'BLOCKED_SECRET') return ['lock', 'bad', 'Secret finding. It was not sent to the AI.'];
  if (item.status === 'BLOCKED_UNKNOWN') return ['lock', 'none', 'Not sent to the AI: the rule behind this finding was not recorded, so it cannot be checked for secrets.'];
  if (item.status === 'PENDING') return ['hourglass_empty', 'none', 'Waiting for its turn.'];
  if (item.status === 'NO_EVIDENCE') return ['report_problem', 'none', 'Nothing was sent to the AI: no evidence could be gathered for this finding (for example its scanned commit or source could not be read). Open the finding and use Ask AI to see the reason.'];
  if (item.status === 'NO_ANSWER') return ['report_problem', 'none', 'The assistant answered, but the answer did not pass the checks (for example it cited lines that were not sent), so it is not shown. Open the finding and use Ask AI to try again.'];
  return DOTS[item.verdict] || ['help_outline', 'none', 'AI advice is available.'];
 }
 function placeDot(findingItem, item) {
  var dot = findingItem.querySelector('[data-ai-dot]');
  if (!dot) { dot = document.createElement('span'); dot.setAttribute('data-ai-dot', ''); dot.tabIndex = 0; findingItem.appendChild(dot); }
  var look = dotFor(item); dot.className = 'wt-ai-dot wt-ai-dot--' + look[1]; dot.replaceChildren(); icon(dot, look[0]); setTip(dot, look[2]); dot.setAttribute('aria-label', look[2]);
 }
 function bindTriage(button) {
  var scope = document.querySelector('[data-scan-type][data-scan-id]');
  if (!scope || !/^(pull_request|repository)$/.test(scope.dataset.scanType)) { button.remove(); return; }
  var workspace = button.closest('[data-finding-workspace]') || document;
  var chipEl = workspace.querySelector('[data-ai-triage-chip]'), seenChip = workspace.querySelector('[data-ai-seen-chip]');
  var label = button.querySelector('[data-ai-triage-label]'), polls = 0, timer = null;
  var type = scope.dataset.scanType, id = Number(scope.dataset.scanId);
  function note(message) {
   chipEl.hidden = false; chipEl.className = 'wt-mini-chip wt-mini-chip--warn';
   chipEl.querySelector('[data-ai-triage-icon]').textContent = 'info'; chipEl.querySelector('[data-ai-triage-text]').textContent = 'Triage unavailable'; setTip(chipEl, message);
  }
  function show(view) {
   var state = view.state, total = view.total || 0, done = view.done || 0;
   if (state !== 'NONE' && !total) { note(view.message || 'Triage is not available.'); return; }
   // Withheld findings (secrets, or a rule that was never recorded) are never asked, so they are not counted as triaged.
   var withheld = view.blocked || 0, askable = Math.max(0, total - withheld), advised = Math.max(0, done - withheld), nothingToAsk = askable === 0;
   var queued = state === 'QUEUED' || state === 'RUNNING';
   button.hidden = queued || state === 'DONE'; label.textContent = state === 'PARTIAL_BUDGET' || state === 'FAILED' ? 'Resume' : 'Triage scan';
   chipEl.hidden = state === 'NONE';
   if (state !== 'NONE') {
    var doneNothing = state === 'DONE' && nothingToAsk;
    chipEl.className = 'wt-mini-chip ' + (queued ? 'wt-ai-triage-chip' : state === 'DONE' && !doneNothing ? 'wt-mini-chip--ok' : 'wt-mini-chip--warn');
    chipEl.querySelector('[data-ai-triage-icon]').textContent = queued ? 'autorenew' : doneNothing ? 'info' : state === 'DONE' ? 'check_circle' : 'pause_circle';
    chipEl.querySelector('[data-ai-triage-text]').textContent = doneNothing ? 'None to triage' : 'Triage ' + advised + '/' + askable + (state === 'PARTIAL_BUDGET' ? ' · limit reached' : state === 'FAILED' ? ' · stopped' : '');
    setTip(chipEl, queued ? 'Working through the findings in the background. You can leave this page.'
      : doneNothing ? 'None of the ' + total + ' findings could be sent: secret findings, and findings whose rule was not recorded, are withheld.'
      : state === 'DONE' ? 'Advice for ' + askable + ' findings' + (withheld ? '; ' + withheld + (withheld === 1 ? ' was' : ' were') + ' not sent (a secret finding, or a finding whose rule was not recorded).' : '.')
      : state === 'PARTIAL_BUDGET' ? (view.limit ? view.limit + ' Resume to finish the rest.' : 'Batch triage reached a daily limit, so it stopped here. Resume to finish the rest.') : 'Triage stopped. Resume to finish the rest.');
   }
   var shown = false;
   (view.items || []).forEach(function (item) {
    var findingItem = Array.prototype.find.call(workspace.querySelectorAll('[data-finding-item]'), function (el) { return el.dataset.feedbackKey === item.key; });
    if (findingItem) { placeDot(findingItem, item); if (item.verdict) shown = true; }
   });
   seenChip.hidden = !shown;
   clearTimeout(timer); if (queued && polls++ < MAX_POLLS) timer = setTimeout(refresh, settings.pollMs);
  }
  async function refresh() { try { show(await api('/assistant/batch-triage/' + type + '/' + id)); } catch (e) { /* the next poll tries again */ } }
  button.addEventListener('click', async function () {
   button.disabled = true;
   try { polls = 0; show(await api('/assistant/batch-triage', 'POST', {scanType: type, scanId: id})); }
   catch (e) { note(e.message); }
   finally { button.disabled = false; }
  });
  refresh();
 }

 /** Rule work → Setup gaps: ask for a CWE for the ticked rules, review the answers, and apply only the ones the person keeps. */
 var CWE_TONES = {high: ['ok', 'High confidence'], medium: ['warn', 'Medium confidence'], low: ['bad', 'Low confidence: check this one']};
 function bindCwe(anchor) {
  var button = anchor.querySelector('[data-work-cwe-open]'), dialog = document.getElementById('cweSuggestDialog');
  if (!button || !dialog) { anchor.remove(); return; }
  var list = dialog.querySelector('[data-cwe-list]'), left = dialog.querySelector('[data-cwe-left]'), status = dialog.querySelector('[data-cwe-status]'),
   apply = dialog.querySelector('[data-cwe-apply]'), label = dialog.querySelector('[data-cwe-apply-label]'), busy = false, applied = false;
  function ticked() { return Array.prototype.slice.call(document.querySelectorAll('[data-work-select]:checked')); }
  function ruleName(id) { var box = document.querySelector('[data-work-select][value="' + Number(id) + '"]'); return box ? String(box.getAttribute('aria-label') || '').replace(/^Select /, '') : 'Rule ' + Number(id); }
  function kept() { return Array.prototype.slice.call(list.querySelectorAll('input[type=checkbox]:checked')); }
  function isStyle(box) { return box.dataset.outcome === 'not_security'; }
  function sync() {
   var picks = kept(), n = picks.length, anyStyle = picks.some(isStyle);
   apply.disabled = busy || applied || n === 0;
   label.textContent = anyStyle ? 'Apply ' + n + (n === 1 ? ' answer' : ' answers') : n === 1 ? 'Apply 1 CWE' : 'Apply ' + n + ' CWEs';
  }
  function reset() { list.replaceChildren(); left.replaceChildren(); status.textContent = ''; applied = false; apply.disabled = true; label.textContent = 'Apply'; }
  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
  function render(result) {
   reset();
   if (result.state !== 'OK') { note(list, 'info', 'warn', result.message || 'CWE suggestions are not available right now.'); return; }
   result.suggestions.forEach(function (s) {
    var row = text(list, 'div', '', 'wt-ai-change'), box = document.createElement('input'), style = s.outcome === 'not_security';
    box.type = 'checkbox'; box.value = String(s.rule_id); box.dataset.cwe = s.cwe; box.checked = s.confidence !== 'low';
    if (style) box.dataset.outcome = 'not_security';
    box.setAttribute('aria-label', style ? 'Mark ' + ruleName(s.rule_id) + ' as not a security rule' : 'Apply ' + s.cwe + ' to ' + ruleName(s.rule_id));
    box.addEventListener('change', sync); row.appendChild(box);
    text(row, 'span', ruleName(s.rule_id));
    if (style) chip(row, 'label_off', 'Not a security rule', '', s.reason);
    else chip(row, '', s.cwe, '', (s.cwe_name ? s.cwe_name + '. ' : '') + s.reason);
    var tone = CWE_TONES[s.confidence] || CWE_TONES.low; chip(row, 'circle', s.confidence, tone[0], tone[1] + '. ' + s.reason);
    // The one-line reason is read, not hovered for
    if (s.reason) text(list, 'p', s.reason, 'wt-field-help wt-ai-reason');
   });
   if (!result.suggestions.length) note(list, 'info', 'info', 'No suggestions for the selected rules.');
   var skipped = result.skipped || {};
   if (result.catalog === false) chip(left, 'menu_book', 'Not checked against the MITRE catalog', 'warn', 'The CWE catalog is not loaded yet. Update it on the Knowledge page so suggestions are checked.');
   if (skipped.secret) chip(left, 'lock', plural(skipped.secret, 'secret rule', 'secret rules') + ' left out', '', 'Rules that detect secrets are never sent to the AI.');
   if (skipped.already_set) chip(left, 'check', plural(skipped.already_set, 'rule already has', 'rules already have') + ' a CWE', '', 'These were not asked about.');
   if (skipped.missing) chip(left, 'help_outline', plural(skipped.missing, 'rule', 'rules') + ' not found', 'warn', 'Reload the page and try again.');
   if (result.stopped === 'BUDGET') note(left, 'hourglass_empty', 'warn', 'Stopped: the daily AI budget is used up. ' + plural(skipped.unanswered || 0, 'rule has', 'rules have') + ' no suggestion.');
   else if (skipped.unanswered) chip(left, 'info', plural(skipped.unanswered, 'rule', 'rules') + ' without a suggestion', '', 'The AI could not tell which CWE fits, or its answer was not usable.');
  }
  button.addEventListener('click', async function () {
   if (busy) return;
   var ids = ticked().map(function (box) { return Number(box.value); }); if (!ids.length) return;
   reset(); status.textContent = 'Asking…'; busy = true; dialog.show();
   try { render(await api('/assistant/cwe-suggestions', 'POST', {ruleIds: ids})); status.textContent = ''; }
   catch (e) { reset(); note(list, e.status === 429 ? 'hourglass_empty' : 'info', 'warn', e.message); }
   finally { busy = false; sync(); }
  });
  apply.addEventListener('click', async function () {
   var picks = kept(); if (busy || applied || !picks.length) return;
   busy = true; sync(); status.textContent = 'Applying…';
   try {
    var done = await api('/rules/work/setup/cwes', 'POST', {assignments: picks.map(function (box) {
     var answer = {ruleId: Number(box.value), cwe: box.dataset.cwe};
     if (isStyle(box)) answer.outcome = 'not_security';
     return answer;
    })});
    applied = true; picks.forEach(function (box) { box.disabled = true; });
    var anyStyle = picks.some(isStyle), tail = done.skipped ? '; ' + plural(done.skipped, 'rule', 'rules') + ' already had one.' : '.';
    status.textContent = (anyStyle ? 'Saved ' : 'Saved a CWE for ') + plural(done.changed, 'rule', 'rules') + tail;
   } catch (e) { status.textContent = e.message; }
   finally { busy = false; sync(); }
  });
  // The list behind the dialog is stale once something was saved, so closing it shows the page again.
  dialog.addEventListener('close', function () { if (applied) window.location.reload(); });
 }

 /**
  * Coverage → a gap: ask the assistant to draft a rule, then open it, unsaved, in the designer. The draft is stored
  * for this person only; the link is followed only when it has exactly the shape of a designer draft link.
  */
 var SCANNER_NAMES = {pmd: 'PMD', opengrep: 'Opengrep', regex: 'Regex', eslint: 'ESLint', json: 'JSON'};
 var DESIGNER_DRAFT_URL = /^\/designer\/(pmd|opengrep|regex|eslint|json)\?draft=[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
 function bindRuleDraft(anchor) {
  var button = anchor.querySelector('[data-gap-suggest]'), dialog = anchor.closest('md-dialog'),
   area = dialog && dialog.querySelector('[data-gap-suggestion]'), busy = false;
  if (!button || !dialog || !area) { anchor.remove(); return; }
  button.addEventListener('click', async function () {
   var cwe = dialog.dataset.cwe, language = dialog.dataset.language;
   if (busy || !cwe || !language) return;
   busy = true; button.disabled = true; area.replaceChildren();
   chip(area, 'hourglass_empty', 'Drafting…', '', 'The assistant is drafting a rule. Nothing is saved.');
   try {
    var result = await api('/assistant/rule-drafts', 'POST', {cwe: cwe, language: language});
    area.replaceChildren();
    if (result.state !== 'OK') { note(area, 'info', 'warn', result.message || 'A drafted rule is not available right now.'); return; }
    var match = DESIGNER_DRAFT_URL.exec(String(result.url));
    if (!match) { note(area, 'info', 'warn', 'The assistant\'s draft could not be opened.'); return; }
    chip(area, 'auto_awesome', 'Suggested scanner: ' + SCANNER_NAMES[match[1]], '', result.reason + ' You can switch scanner in the designer. Nothing is saved yet.');
    var link = document.createElement('a'); link.className = 'wt-mini-chip wt-mini-chip--link'; link.href = result.url;
    icon(link, 'build'); link.appendChild(document.createTextNode('Open in the designer'));
    setTip(link, 'Opens the drafted rule with its example. You review it and save it yourself.'); area.appendChild(link);
   } catch (e) { area.replaceChildren(); note(area, e.status === 429 ? 'hourglass_empty' : 'info', 'warn', e.message); }
   finally { busy = false; button.disabled = false; }
  });
 }

 /** Scan reports: the AI review of picked files is drawn by ai-review.js, which needs the fetch helper and the helper flags. */
 function bindAiReview(button) {
  if (window.WatchtowerAiReview) window.WatchtowerAiReview.bind(button, {api: api, flags: helperFlags}); else button.remove();
 }

 /**
  * Knowledge → Propose dialog: fill the form from the evidence already chosen in it. It only writes into the form
  * fields; the person checks them and presses Propose, and a second person approves.
  */
 var KNOWLEDGE_DRAFT_MAX_EVIDENCE = 5;
 function bindKnowledgeDraft(anchor) {
  var button = anchor.querySelector('[data-knowledge-draft]'), dialog = anchor.closest('md-dialog'),
   chosen = dialog && dialog.querySelector('[data-knowledge-picker="evidence"] [data-picker-selected]'),
   status = dialog && dialog.querySelector('form [data-knowledge-status]'), busy = false;
  if (!button || !dialog || !chosen || !status) { anchor.remove(); return; }
  function refs() {
   return Array.prototype.slice.call(chosen.querySelectorAll('li[data-picker-value]')).map(function (li) {
    return {type: li.dataset.pickerType, id: li.dataset.pickerValue};
   });
  }
  function sync() { button.disabled = busy || refs().length === 0; }
  /** The answer sits under the evidence: a refusal in the warning tone, anything else neutral, and always in view. */
  function say(text, tone) {
   status.textContent = text;
   status.className = 'wt-ai-note wt-ai-note--' + tone;
   if (text && typeof status.scrollIntoView === 'function') status.scrollIntoView({block: 'nearest'});
  }
  function fill(selector, value) {
   var field = dialog.querySelector(selector);
   if (field && value) field.value = value;
  }
  // An answer or refusal is about the evidence that was chosen; other evidence ends it (not while a draft is being asked for)
  new MutationObserver(function () { if (!busy) say('', 'info'); sync(); }).observe(chosen, {childList: true});
  sync();
  button.addEventListener('click', async function () {
   var evidence = refs();
   if (busy || !evidence.length) return;
   if (evidence.length > KNOWLEDGE_DRAFT_MAX_EVIDENCE) { say('Choose at most ' + KNOWLEDGE_DRAFT_MAX_EVIDENCE + ' pieces of evidence to draft from.', 'warn'); return; }
   busy = true; sync(); say('Drafting…', 'info');
   try {
    var result = await api('/assistant/knowledge-draft', 'POST', {evidence: evidence});
    if (result.state !== 'OK') { say(result.message || 'A draft is not available right now.', 'warn'); return; }
    var f = result.fields || {};
    fill('[data-knowledge-kind]', f.kind); fill('[data-knowledge-statement]', f.statement); fill('[data-knowledge-language]', f.language);
    fill('[data-knowledge-library]', f.library); fill('[data-knowledge-versions]', f.version_range);
    fill('[data-knowledge-cwes]', (f.cwes || []).join(', '));
    say('Drafted by the assistant from the chosen evidence. Check every field before you propose.'
     + (result.reason ? ' Why: ' + result.reason : ''), 'info');
   } catch (e) { say(e.message, 'warn'); }
   finally { busy = false; sync(); }
  });
 }

 var BINDERS = {draft: bindDraft, bypass: bindBypass, diagnose: bindDiagnose, triage: bindTriage, onboarding: bindOnboarding, fixture: bindFixture, alerts: bindAlerts, cwe: bindCwe, ruleDraft: bindRuleDraft, aiReview: bindAiReview, knowledgeDraft: bindKnowledgeDraft};
 /** Shows each helper on the page that the server says is ready for this person; a page with none costs no request. */
 async function init() {
  var places = Array.prototype.slice.call(document.querySelectorAll('[data-ai-helper]')).filter(function (el) { return !el.dataset.aiBound; });
  if (!places.length || !drawer()) return;
  var flags = await helperFlags();
  places.forEach(function (el) {
   if (el.dataset.aiBound) return; el.dataset.aiBound = 'true';
   var kind = el.dataset.aiHelper;
   if (!flags[kind] || !BINDERS[kind]) { el.remove(); return; }
   el.hidden = false; BINDERS[kind](el);
  });
 }
 window.WatchtowerAiHelpers = {collectDraft: collectDraft, settings: settings,
  alerts: {name: alertName, icon: alertIcon, routeLine: routeLine, settingChips: settingChips, kindChip: kindChip, chip: chip, text: text, note: note}};
 document.addEventListener('htmx:afterSettle', init);
 if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();

(function () {
 'use strict';
 // Review a drafted set of alert-route changes (alert copilot board, approved 2026-10-24). The page reads the
 // draft from the server, shows what each change does, and applies it only when the person presses Approve.
 // All text is set with textContent.
 var root = document.querySelector('[data-alert-change-set]');
 if (!root || root.dataset.ready) return;
 root.dataset.ready = 'true';
 var base = '/assistant/alert-changes/' + encodeURIComponent(root.dataset.id);
 var rows = root.querySelector('[data-ac-rows]'), chips = root.querySelector('[data-ac-chips]'), status = root.querySelector('[data-ac-status]');
 var apply = root.querySelector('[data-ac-apply]'), cancel = root.querySelector('[data-ac-cancel]'), refresh = root.querySelector('[data-ac-refresh]'), back = root.querySelector('[data-ac-back]');
 var data = null, stale = false, refreshFailed = false, busy = false, timer = null;

 function h() { return window.WatchtowerAiHelpers && window.WatchtowerAiHelpers.alerts; }
 async function request(path, body) {
  var headers = {Accept: 'application/json'};
  if (body !== undefined) { headers['Content-Type'] = 'application/json'; headers[root.dataset.csrfHeader] = root.dataset.csrfToken; }
  var response = await fetch(base + path, {method: body === undefined ? 'GET' : 'POST', headers: headers, body: body === undefined ? undefined : JSON.stringify(body)});
  var payload = {};
  try { payload = await response.json(); } catch (e) { payload = {}; }
  if (!response.ok) { var error = new Error(payload.error || payload.message || 'This is unavailable right now (' + response.status + ').'); error.code = payload.code; throw error; }
  return payload;
 }

 function expired() { return !!data && data.status === 'DRAFT' && Date.now() >= data.expiresAt; }
 /** The state chip after the fixed "Drafted by the assistant" chip. */
 function stateChip() {
  Array.prototype.forEach.call(chips.querySelectorAll('[data-ac-dynamic]'), function (el) { el.remove(); });
  var a = h(), el = null;
  if (data.status === 'APPLIED') {
   var receipt = data.receipt || {};
   el = a.chip(chips, 'check_circle', 'Applied by ' + (receipt.actor || 'someone') + (receipt.appliedAt ? ' · ' + new Date(receipt.appliedAt).toLocaleString() : ''), 'ok', 'These changes are saved. Applying again changes nothing more.');
  } else if (data.status === 'CANCELED') el = a.chip(chips, 'cancel', 'Canceled', '', 'This draft was canceled and changed nothing.');
  else if (expired()) el = a.chip(chips, 'timer_off', 'Approval expired', 'bad', 'Approval lasts 30 minutes. Refresh the preview to start a new 30 minutes.');
  else if (stale) el = a.chip(chips, 'sync_problem', 'Routes changed since this draft', 'warn', 'Someone edited alert routes after the draft was made. Refresh the preview, check it, and approve again.');
  else {
   var minutes = Math.max(1, Math.ceil((data.expiresAt - Date.now()) / 60000));
   el = a.chip(chips, 'timer', 'Expires in ' + minutes + ' min', 'warn', 'Approval lasts 30 minutes and applies to exactly these changes.');
  }
  if (el) el.setAttribute('data-ac-dynamic', '');
 }
 function buttons() {
  var draft = !!data && data.status === 'DRAFT', done = !!data && data.status === 'APPLIED';
  apply.hidden = cancel.hidden = refresh.hidden = !!data && !draft;
  apply.disabled = busy || !draft || stale || expired();
  cancel.disabled = busy || !draft;
  refresh.disabled = busy || !draft;
  back.hidden = !(done || (!!data && data.status === 'CANCELED') || (stale && refreshFailed));
 }

 function renderRows() {
  var a = h();
  rows.replaceChildren();
  ((data.preview && data.preview.changes) || []).forEach(function (change) {
   var tr = document.createElement('tr'); rows.appendChild(tr);
   var kind = document.createElement('td'); tr.appendChild(kind); a.kindChip(kind, change.type);
   var route = document.createElement('td'); tr.appendChild(route); a.routeLine(route, change.after || change.before);
   var before = document.createElement('td'), after = document.createElement('td'); tr.appendChild(before); tr.appendChild(after);
   var chipsBefore = a.text(before, 'span', '', 'wt-meta-chips'), chipsAfter = a.text(after, 'span', '', 'wt-meta-chips');
   if (change.type === 'ADD') { a.text(chipsBefore, 'span', 'No route', 'wt-field-help'); a.settingChips(chipsAfter, change.after, null, ''); }
   else if (change.type === 'REMOVE') { a.settingChips(chipsBefore, change.before, null, ''); a.text(chipsAfter, 'span', 'Route removed. It stops sending alerts.', 'wt-field-help'); }
   else { a.settingChips(chipsBefore, change.before, change.after, 'warn'); a.settingChips(chipsAfter, change.after, change.before, 'ok'); }
  });
 }
 function render(next) {
  data = next;
  stale = false; refreshFailed = false;
  renderRows(); stateChip(); buttons();
  status.textContent = data.status === 'APPLIED' ? 'Applied. The routes now match this draft.' : data.status === 'CANCELED' ? 'Canceled. Nothing was changed.' : expired() ? 'This approval expired. Refresh the preview to look again.' : '';
  clearInterval(timer);
  if (data.status === 'DRAFT') timer = setInterval(function () { if (data) { stateChip(); buttons(); } }, 30000);
 }
 async function act(path, body, onError) {
  busy = true; buttons();
  try { render(await request(path, body)); }
  catch (e) { (onError || function (err) { status.textContent = err.message; })(e); }
  busy = false; buttons();
 }
 apply.addEventListener('click', function () {
  if (!data) return;
  act('/apply', {version: data.version, contentHash: data.contentHash}, function (e) {
   if (e.code === 'STALE_STATE') { stale = true; stateChip(); }
   else if (e.code === 'APPROVAL_EXPIRED') { data.expiresAt = 0; stateChip(); }
   status.textContent = e.message;
  });
 });
 cancel.addEventListener('click', function () { act('/cancel', {}); });
 refresh.addEventListener('click', function () {
  act('/refresh', {}, function (e) {
   // A draft made against routes that have since changed cannot be refreshed; the person asks the assistant again.
   if (e.code === 'STALE_STATE') { stale = true; refreshFailed = true; stateChip(); }
   status.textContent = e.message;
  });
 });
 function start() { request('').then(render).catch(function (e) { status.textContent = e.message; }); }
 if (h()) start(); else window.addEventListener('load', start);
}());

(function () {
 'use strict';
 if (window.wtRuleReviewsInstalled) return;
 window.wtRuleReviewsInstalled = true;
 var STATUS = {OPEN: 'Open', IN_REVIEW: 'In review', ACCEPTED: 'Accepted', REJECTED: 'Rejected', CLOSED: 'Closed'};
 // A choice drawn as radio chips reads like a field: the checked radio's value.
 function read(element) {
  if (!element) return '';
  var radios = element.querySelectorAll('input[type="radio"]');
  if (!radios.length) return element.value || '';
  var checked = Array.prototype.find.call(radios, function (radio) { return radio.checked; });
  return checked ? checked.value : '';
 }
 function initialize() {
  document.querySelectorAll('[data-rule-review-page]').forEach(function (root) {
   if (root.dataset.ready) return; root.dataset.ready = 'true';
   var id = root.dataset.reviewId || null, version = Number(root.dataset.reviewVersion || 0);
   var revision = id ? root.dataset.reviewRevision || null : root.dataset.ruleRevision || null;
   var evidence = null, evidencePage = 0, evidenceGeneration = 0, timer, saving = false;
   var historyPage = 0, historyGeneration = 0;
   var status = root.querySelector('[data-rule-review-status]');
   function value(name) { return read(root.querySelector('[data-' + name + ']')); }
   function picker() { var area = root.querySelector('[data-evidence-picker]'); if (area) area.hidden = !value('evidence-kind'); }
   async function api(url, body) {
    var options = {};
    if (body) { var headers = {'Content-Type': 'application/json'}; headers[root.dataset.csrfHeader] = root.dataset.csrfToken; options = {method: 'POST', headers: headers, body: JSON.stringify(body)}; }
    var response = await fetch(url, options);
    if (!response.ok) throw new Error(response.status === 409 ? 'This review or rule revision changed. Your input is preserved. Check the latest record before retrying.' : 'Request failed (' + response.status + '). Your input is preserved. Check access, selected evidence and required fields, then retry.');
    return response.json();
   }
   async function loadEvidence() {
    var generation = ++evidenceGeneration, kind = value('evidence-kind');
    var area = root.querySelector('[data-evidence-options]'), info = root.querySelector('[data-evidence-status]');
    area.replaceChildren();
    if (!kind) { evidence = null; info.textContent = ''; root.querySelector('[data-evidence-preview]').textContent = ''; return; }
    info.textContent = 'Loading authorized evidence…';
    try {
     var params = new URLSearchParams({kind: kind, revision: revision || 'unknown', search: value('evidence-search'), page: evidencePage});
     var result = await api('/rules/' + root.dataset.ruleId + '/reviews/evidence?' + params);
     if (generation !== evidenceGeneration || !root.isConnected) return;
     result.content.forEach(function (item) {
      var label = document.createElement('label'), input = document.createElement('input');
      input.type = 'radio'; input.name = 'review-evidence'; input.value = item.id; input.checked = !!evidence && evidence.id === item.id && evidence.type === item.type;
      label.append(input, document.createTextNode(' ' + item.label));
      input.addEventListener('change', function () { evidence = item; root.querySelector('[data-evidence-preview]').textContent = item.preview; });
      area.appendChild(label);
     });
     info.textContent = result.totalElements ? result.totalElements + ' records · page ' + (evidencePage + 1) + ' of ' + result.totalPages : 'No eligible records for this revision and search. Save feedback or a reviewed example, or attach the revision itself.';
     root.querySelector('[data-evidence-previous]').disabled = evidencePage === 0;
     root.querySelector('[data-evidence-next]').disabled = evidencePage + 1 >= result.totalPages;
    } catch (error) { if (generation === evidenceGeneration) info.textContent = error.message; }
   }
   var kind = root.querySelector('[data-evidence-kind]');
   if (kind) {
    kind.addEventListener('change', function () { evidence = null; evidencePage = 0; root.querySelector('[data-evidence-preview]').textContent = ''; picker(); loadEvidence(); });
    picker();
    root.querySelector('[data-evidence-search]').addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(function () { evidencePage = 0; loadEvidence(); }, 200); });
    root.querySelector('[data-evidence-previous]').addEventListener('click', function () { if (evidencePage > 0) { evidencePage--; loadEvidence(); } });
    root.querySelector('[data-evidence-next]').addEventListener('click', function () { evidencePage++; loadEvidence(); });
   }
   async function history() {
    if (!id || !root.querySelector('[data-review-history]')) return;
    var generation = ++historyGeneration, info = root.querySelector('[data-review-history-status]');
    try {
     var result = await api('/rules/' + root.dataset.ruleId + '/reviews/' + id + '/history?page=' + historyPage);
     if (generation !== historyGeneration || !root.isConnected) return;
     var area = root.querySelector('[data-review-history]'); area.replaceChildren();
     result.content.forEach(function (item) { var entry = document.createElement('p'); entry.textContent = (STATUS[item.status] || item.status) + ' · ' + item.actor + ' · ' + (window.WatchtowerTime ? window.WatchtowerTime.format(item.changedAt) : new Date(item.changedAt).toLocaleString(undefined, {timeZoneName: 'short'})) + ' · ' + item.outcome; area.appendChild(entry); });
     info.textContent = result.totalElements + ' saved decisions';
     root.querySelector('[data-history-previous]').disabled = historyPage === 0;
     root.querySelector('[data-history-next]').disabled = historyPage + 1 >= result.totalPages;
    } catch (error) { if (generation === historyGeneration) info.textContent = error.message; }
   }
   if (root.querySelector('[data-review-history-section]')) {
    root.querySelector('[data-history-previous]').addEventListener('click', function () { if (historyPage > 0) { historyPage--; history(); } });
    root.querySelector('[data-history-next]').addEventListener('click', function () { historyPage++; history(); }); history();
   }
   var form = root.querySelector('[data-rule-review-form]');
   if (form) form.addEventListener('submit', async function (event) {
    event.preventDefault(); if (saving) return;
    if (!id && kind && value('evidence-kind') && !evidence) { status.textContent = 'Select and preview an evidence record, or choose no attached evidence.'; return; }
    saving = true; root.querySelector('[data-review-save]').disabled = true;
    try {
     var result = await api('/rule/evidence/reviews', {id: id, ruleId: Number(root.dataset.ruleId), revision: revision, owner: value('review-owner'), status: value('review-state'), reason: value('review-reason'), recommendation: value('review-recommendation'), outcome: value('review-outcome'), evidenceType: evidence ? evidence.type : null, evidenceId: evidence ? evidence.id : null, sessionId: null, turnId: null, version: version});
     id = result.id; version++; root.dataset.reviewId = id; root.dataset.reviewVersion = version;
     var fieldset = root.querySelector('[data-review-evidence]'); if (fieldset) fieldset.disabled = true;
     status.textContent = 'Review saved. Enforcement is unchanged. ';
     var link = document.createElement('a'); link.href = '/rules/' + root.dataset.ruleId + '/reviews?reviewId=' + encodeURIComponent(id) + '&revision=' + (revision || 'unknown'); link.textContent = 'Open saved review and history'; status.appendChild(link);
     historyPage = 0; history();
    } catch (error) { status.textContent = error.message; }
    finally { saving = false; root.querySelector('[data-review-save]').disabled = false; }
   });
   var caseForm = root.querySelector('[data-review-case-form]');
   if (caseForm) caseForm.addEventListener('submit', async function (event) {
    event.preventDefault(); if (caseForm.dataset.saving) return; caseForm.dataset.saving = 'true';
    var info = root.querySelector('[data-case-status]');
    try { var result = await api('/rule/evidence/cases', {ruleId: Number(root.dataset.ruleId), revision: root.dataset.ruleRevision || null, kind: value('case-kind'), fixtureRef: value('case-reference'), fixtureHash: value('case-hash'), expectedBehavior: value('case-expected'), engine: value('case-engine'), language: value('case-language')});
     info.textContent = 'Example reference saved. It has not been executed. ';
     var link = document.createElement('a'); link.href = '/rules/' + root.dataset.ruleId + '/candidates?caseId=' + encodeURIComponent(result.id); link.textContent = 'Prepare executable fixture'; info.appendChild(link);
    } catch (error) { info.textContent = error.message; }
    finally { delete caseForm.dataset.saving; }
   });
   // The search filters as you type; a saved review (or a "New review" link) opens its dialog.
   var search = root.querySelector('[data-review-search]'), filterTimer;
   if (search) search.addEventListener('input', function () {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(function () { var filters = search.closest('form'); if (filters && filters.requestSubmit) filters.requestSubmit(); }, 400);
   });
   var dialog = root.querySelector('[data-review-dialog]');
   if (dialog && root.dataset.openOnLoad === 'true') {
    var show = function () { if (typeof dialog.show === 'function') dialog.show(); };
    if (window.customElements && window.customElements.whenDefined) window.customElements.whenDefined('md-dialog').then(show); else show();
   }
  });
 }
 document.addEventListener('DOMContentLoaded', initialize); document.addEventListener('htmx:afterSwap', initialize); initialize();
})();

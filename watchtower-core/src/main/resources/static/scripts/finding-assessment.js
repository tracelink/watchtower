(function () {
  'use strict';
  // Plan R6: an advisory AI second opinion on one finding, fetched only when the person asks for it,
  // so opening the judgment dialog never counts as having seen the AI verdict.
  var VERDICTS = {LIKELY_TRUE_POSITIVE: 'Likely true positive', LIKELY_FALSE_POSITIVE: 'Likely false positive',
    NEEDS_REVIEW: 'Needs review', INSUFFICIENT_EVIDENCE: 'Insufficient evidence'};
  var CRITERIA = {input_reaches_sink: 'Input reaches sink', sanitized: 'Sanitized', test_or_generated_code: 'Test or generated code',
    matches_rule_intent: 'Matches the rule’s intent'};
  var generation = 0;
  function dialog() { return document.querySelector('[data-feedback-dialog]'); }
  function text(parent, tag, value) { var el = document.createElement(tag); el.textContent = value; parent.appendChild(el); return el; }
  function render(area, a) {
    area.replaceChildren();
    if (a.state !== 'ASSESSED') { text(area, 'p', a.message || 'No AI assessment is available.'); return; }
    var head = text(area, 'p', '');
    var chip = text(head, 'span', 'AI (advisory): ' + (VERDICTS[a.verdict] || a.verdict));
    chip.className = 'wt-status-chip';
    var list = text(area, 'ul', '');
    Object.keys(CRITERIA).forEach(function (key) {
      var c = a.criteria[key];
      if (c) text(list, 'li', CRITERIA[key] + ': ' + c.answer + ' — ' + c.reason);
    });
    var cited = [];
    if (a.cited_lines.length) cited.push('lines ' + a.cited_lines.join(', '));
    if (a.knowledge_ids.length) cited.push('approved knowledge ' + a.knowledge_ids.join(', '));
    var meta = text(area, 'p', (cited.length ? 'Cites ' + cited.join('; ') + '. ' : '') + a.model + ', ' + (window.WatchtowerTime ? window.WatchtowerTime.format(a.created_at) : new Date(a.created_at).toLocaleString(undefined, {timeZoneName: 'short'})) + '. ' + a.note);
    meta.className = 'wt-page-meta';
  }
  async function ask() {
    var d = dialog(), area = d.querySelector('[data-assessment-result]');
    var keys = Array.from(d.querySelectorAll('[data-feedback-selection] input:checked')).map(function (i) { return i.value; });
    if (keys.length !== 1) { area.textContent = 'Select exactly one finding to ask about.'; return; }
    var mine = ++generation, button = d.querySelector('[data-assessment-ask]');
    area.textContent = 'Asking…';
    button.disabled = true;
    var headers = {'Content-Type': 'application/json'};
    headers[d.dataset.csrfHeader] = d.dataset.csrfToken;
    var response, body = {};
    try {
      response = await fetch('/finding-assessment', {method: 'POST', headers: headers,
        body: JSON.stringify({scanType: d.dataset.scanType, scanId: Number(d.dataset.scanId), findingKey: keys[0]})});
      try { body = await response.json(); } catch (e) { body = {}; }
    } finally { button.disabled = false; }
    // The selection changed or the dialog reopened while asking: this answer belongs to another finding.
    if (mine !== generation) return;
    if (!response.ok) { area.textContent = body.error || body.message || 'The AI assessment is unavailable (' + response.status + ').'; return; }
    render(area, body);
  }
  function clear() { generation++; var area = dialog() && dialog().querySelector('[data-assessment-result]'); if (area) area.replaceChildren(); }
  // A previous answer never carries over to another finding.
  document.addEventListener('change', function (event) { if (event.target.closest('[data-feedback-selection]')) clear(); });
  document.addEventListener('click', function (event) {
    var d = dialog();
    if (!d) return;
    if (event.target.closest('[data-feedback-open], [data-feedback-close]')) { clear(); return; }
    if (!event.target.closest('[data-assessment-ask]')) return;
    ask().catch(function (e) { d.querySelector('[data-assessment-result]').textContent = e.message; });
  });
})();

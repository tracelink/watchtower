(function () {
  'use strict';
  var offset = 0;
  var EVIDENCE = {SECURITY_FIX: 'Security fix', PENTEST: 'Pentest', MANUAL: 'Other confirmed miss'};
  // A text field's value, or the chosen button of a row of choices (Evidence).
  function valueOf(field) {
    if (field.matches('fieldset')) {
      var chosen = field.querySelector('input:checked');
      return chosen ? chosen.value : '';
    }
    return String(field.value || '').trim();
  }
  function dialog() { return document.querySelector('[data-missed-dialog]'); }
  async function cases(d) {
    var response = await fetch('/repository/evidence/missed/' + d.dataset.repoId + '?offset=' + offset);
    if (!response.ok) throw new Error('Reviewed cases unavailable (' + response.status + ').');
    var rows = await response.json(), area = d.querySelector('[data-missed-list]');
    area.replaceChildren();
    if (!rows.length) {
      var none = document.createElement('p');
      none.className = 'wt-field-help';
      none.textContent = offset === 0 ? 'No cases recorded for this repository yet.' : 'No more cases.';
      area.appendChild(none);
    }
    rows.forEach(function (row) {
      // One line per case: what, where and who; the full commit is the hover text.
      var item = document.createElement('div');
      item.className = 'wt-missed-case';
      var label = document.createElement('span');
      label.textContent = (EVIDENCE[row.evidence_type] || row.evidence_type) + ' · ' + row.cwe + ' · ' + row.affected_path + ':' + row.first_line + ' · reviewed by ' + row.reviewer;
      label.title = 'Commit ' + row.commit_hash + (row.fixture_ref ? ' · example ' + row.fixture_ref : '');
      item.appendChild(label);
      // R5.3: open the step-by-step "Find similar code" dialog for this case.
      var similar = document.createElement('button');
      similar.type = 'button'; similar.className = 'btn btn-secondary btn-sm';
      var icon = document.createElement('span'); icon.className = 'material-icons'; icon.setAttribute('aria-hidden', 'true'); icon.textContent = 'manage_search';
      similar.appendChild(icon); similar.appendChild(document.createTextNode('Find similar code'));
      similar.dataset.variantOpen = row.case_id;
      similar.dataset.caseSummary = row.cwe + ' in ' + row.affected_path + ':' + row.first_line;
      if (row.rule_id) similar.dataset.ruleId = row.rule_id;
      item.appendChild(similar);
      area.appendChild(item);
    });
    d.querySelector('[data-missed-previous]').disabled = offset === 0;
    d.querySelector('[data-missed-next]').disabled = rows.length < 20;
  }
  document.addEventListener('click', async function (event) {
    var d = dialog(); if (!d) return;
    var status = d.querySelector('[data-missed-status]');
    try {
      if (event.target.closest('[data-missed-open]')) { offset = 0; status.textContent = ''; await d.show(); await cases(d); }
      if (event.target.closest('[data-missed-close]')) d.close();
      if (event.target.closest('[data-missed-next]')) { offset += 20; await cases(d); }
      if (event.target.closest('[data-missed-previous]')) { offset = Math.max(0, offset - 20); await cases(d); }
      var save = event.target.closest('[data-missed-save]');
      if (save && !save.disabled) {
        save.disabled = true;
        try {
          var body = {repositoryId: Number(d.dataset.repoId), ruleId: null, revision: null};
          d.querySelectorAll('[data-missed-field]').forEach(function (field) { body[field.dataset.missedField] = valueOf(field); });
          body.firstLine = Number(body.firstLine); body.fixedCommit = body.fixedCommit || null;
          var headers = {'Content-Type': 'application/json'}; headers[d.dataset.csrfHeader] = d.dataset.csrfToken;
          var response = await fetch('/repository/evidence/missed', {method: 'POST', headers: headers, body: JSON.stringify(body)});
          if (!response.ok) throw new Error('Case could not be saved (' + response.status + '). Check the pinned commits and reviewed fixture reference.');
          status.textContent = 'Confirmed case saved. Scan enforcement is unchanged.'; offset = 0; await cases(d);
        } finally { save.disabled = false; }
      }
    } catch (error) { status.textContent = error.message; }
  });
})();

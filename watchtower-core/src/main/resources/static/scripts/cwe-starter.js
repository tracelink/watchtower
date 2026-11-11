(function () {
  'use strict';
  // Rule work, Setup gaps: "Fill from starter map". The dialog previews which rules without a CWE would get
  // one from the curated list; nothing is saved until Apply. Text from the server is only written as text.
  var dialog = document.querySelector('[data-cwe-starter-dialog]');
  if (!dialog || dialog.dataset.starterReady) return;
  dialog.dataset.starterReady = 'true';
  var STARTER_URL = '/rules/coverage/starter';
  var SHOWN = 50;
  var RELOAD_DELAY_MS = 900;
  var apply = dialog.querySelector('[data-starter-apply]');
  var label = dialog.querySelector('[data-starter-apply-label]');
  var statusLine = dialog.querySelector('[data-starter-status]');
  var pending = 0;

  function make(tag, className, value) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (value !== undefined) node.textContent = value;
    return node;
  }
  function chip(parent, text, iconName, tone, tip) {
    var node = make('span', 'wt-mini-chip' + (tone ? ' wt-mini-chip--' + tone : ''));
    if (tip) { node.tabIndex = 0; node.setAttribute('data-tip', tip); }
    var glyph = make('span', 'material-icons', iconName);
    glyph.setAttribute('aria-hidden', 'true');
    node.appendChild(glyph);
    node.appendChild(make('span', '', text));
    parent.appendChild(node);
  }
  async function call(options) {
    var response = await window.fetch(STARTER_URL, options);
    var body = {};
    try { body = await response.json(); } catch (e) { body = {}; }
    if (!response.ok) throw new Error(body.error || 'That did not work (' + response.status + ').');
    return body;
  }

  function draw(preview) {
    var chips = dialog.querySelector('[data-starter-chips]');
    var list = dialog.querySelector('[data-starter-list]');
    chips.replaceChildren();
    list.replaceChildren();
    pending = preview.proposals.length;
    apply.disabled = pending === 0;
    label.textContent = pending ? 'Apply to ' + pending + (pending === 1 ? ' rule' : ' rules') : 'Apply';
    chip(chips, pending + (pending === 1 ? ' rule' : ' rules') + ' would get a CWE', pending ? 'playlist_add_check' : 'check_circle', pending ? 'ok' : '',
      'Only rules without a CWE that are not marked as not a security rule.');
    if (preview.skippedUnknownCwe) {
      chip(chips, preview.skippedUnknownCwe + ' skipped', 'report_problem', 'warn',
        'The starter CWE is not in the loaded catalog, or MITRE now discourages it.');
    }
    if (!pending) return;
    var table = make('table', 'table mb-0');
    var body = make('tbody');
    preview.proposals.slice(0, SHOWN).forEach(function (proposal) {
      var row = make('tr');
      var name = make('th', '', proposal.name);
      name.scope = 'row';
      row.appendChild(name);
      row.appendChild(make('td', 'wt-muted', proposal.module));
      var cell = make('td');
      chip(cell, proposal.cwe, 'shield', '', proposal.cweName);
      row.appendChild(cell);
      body.appendChild(row);
    });
    table.appendChild(body);
    list.appendChild(table);
    if (pending > SHOWN) list.appendChild(make('span', 'wt-field-help', '+ ' + (pending - SHOWN) + ' more'));
  }

  async function preview() {
    statusLine.textContent = '';
    apply.disabled = true;
    try {
      draw(await call({headers: {Accept: 'application/json'}}));
    } catch (error) {
      dialog.querySelector('[data-starter-chips]').replaceChildren();
      dialog.querySelector('[data-starter-list]').replaceChildren();
      statusLine.textContent = error.message;
    }
  }

  async function save() {
    apply.disabled = true;
    var headers = {Accept: 'application/json'};
    headers[dialog.dataset.csrfHeader] = dialog.dataset.csrfToken;
    try {
      var answer = await call({method: 'POST', headers: headers});
      statusLine.textContent = 'Updated ' + answer.changed + (answer.changed === 1 ? ' rule' : ' rules') + '.';
      window.setTimeout(function () { window.location.reload(); }, RELOAD_DELAY_MS);
    } catch (error) {
      statusLine.textContent = error.message;
      apply.disabled = false;
    }
  }

  document.addEventListener('click', function (event) {
    if (!(event.target instanceof Element)) return;
    if (event.target.closest('[data-cwe-starter-open]')) preview();
    else if (event.target.closest('[data-starter-apply]')) save();
  });
})();

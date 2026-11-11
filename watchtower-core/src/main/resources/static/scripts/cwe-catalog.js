(function () {
  'use strict';
  // Knowledge page: the CWE catalog chip and its update button. The server renders the chip; this script
  // asks for an update, then follows it until it ends. Text from the server is only ever written as text.
  var STATE_URL = '/rules/knowledge/cwe-catalog';
  var POLL_MS = 3000;
  var MAX_POLLS = 400; // about twenty minutes, the most an update is allowed to take
  var root = document.querySelector('[data-knowledge-page]');
  var chip = root && root.querySelector('[data-cwe-catalog]');
  if (!chip) return;
  var button = root.querySelector('[data-cwe-catalog-update]');
  var polls = 0;

  function render(view) {
    chip.dataset.state = view.state;
    chip.dataset.tip = view.tip;
    chip.classList.remove('wt-mini-chip--warn', 'wt-mini-chip--info');
    if (view.tone) chip.classList.add('wt-mini-chip--' + view.tone);
    var icon = chip.querySelector('[data-cwe-catalog-icon]');
    if (icon) icon.textContent = view.icon;
    chip.querySelector('[data-cwe-catalog-label]').textContent = view.label;
    if (button) button.disabled = !!view.updating;
    if (view.updating) schedulePoll();
  }

  function note(message) {
    chip.dataset.tip = message;
    if (button) button.disabled = false;
  }

  function schedulePoll() {
    if (polls >= MAX_POLLS) {
      note('Still updating. Reload this page to check again.');
      return;
    }
    polls += 1;
    window.setTimeout(poll, POLL_MS);
  }

  async function poll() {
    try {
      var response = await window.fetch(STATE_URL, {headers: {Accept: 'application/json'}});
      if (!response.ok) throw new Error('state ' + response.status);
      render(await response.json());
    } catch (error) {
      note('Could not read the update status. Reload this page to check again.');
    }
  }

  async function update() {
    if (button) button.disabled = true;
    try {
      var headers = {};
      headers[root.dataset.csrfHeader] = root.dataset.csrfToken;
      var response = await window.fetch(STATE_URL + '/refresh?force=false', {method: 'POST', headers: headers});
      if (!response.ok) throw new Error('refresh ' + response.status);
      polls = 0;
      var answer = await response.json();
      render(answer.chip);
      if (!answer.queued && !answer.chip.updating) note('The update could not be queued. Try again in a moment.');
    } catch (error) {
      note('The update could not start. You may not have permission, or the server is busy.');
    }
  }

  if (button) button.addEventListener('click', update);
  if (chip.dataset.state === 'UPDATING') schedulePoll();
})();

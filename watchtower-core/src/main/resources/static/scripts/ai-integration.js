(function () {
  'use strict';
  // AI integration: add, replace, remove and test the OpenAI key. The key is write-only: the server
  // stores it (encrypted when database encryption is on) and only ever returns whether one is
  // configured. The state is three chips; the key field appears only to add or replace a key.
  var PATH = '/admin/assistant/integrations/openai';
  var ERRORS = {
    PROVIDER_AUTHENTICATION: 'OpenAI rejected the key', API_KEY_REJECTED: 'OpenAI rejected the key',
    PROVIDER_TRANSPORT: "Couldn't reach OpenAI", PROVIDER_UNAVAILABLE: 'OpenAI was unavailable',
    PROVIDER_RATE_LIMIT: 'OpenAI rate limit reached', PROVIDER_PROTOCOL: 'OpenAI sent an unexpected reply', NO_API_KEY: 'No key saved'
  };
  var version = null, configured = false, replacing = false;
  function root() { return document.querySelector('[data-assistant-admin]'); }
  function dialog() { return document.querySelector('[data-ai-integration-dialog]'); }
  function el(name) { return dialog().querySelector('[data-ai-integration-' + name + ']'); }
  function status(value) { el('status').textContent = value; }
  async function api(path, data) {
    var options = {headers: {'Content-Type': 'application/json'}};
    if (data !== undefined) { options.method = 'POST'; options.body = JSON.stringify(data); options.headers[root().dataset.csrfHeader] = root().dataset.csrfToken; }
    var response = await fetch(PATH + path, options), body = {};
    try { body = await response.json(); } catch (e) { body = {}; }
    if (!response.ok) throw new Error(body.error || 'Request failed (' + response.status + ').');
    return body;
  }
  function when(millis) { return (window.WatchtowerTime ? window.WatchtowerTime.format(millis) : new Date(millis).toLocaleString(undefined, {timeZoneName: 'short'})); }
  function brief(millis) { return window.WatchtowerTime && window.WatchtowerTime.short ? window.WatchtowerTime.short(millis) : when(millis); }
  function words(code) { return ERRORS[code] || 'The test failed'; }
  function chip(label, icon, tone, tip) {
    var element = document.createElement('span');
    element.className = 'wt-mini-chip' + (tone ? ' wt-mini-chip--' + tone : '');
    element.tabIndex = 0;
    element.dataset.tip = tip;
    element.setAttribute('aria-label', label + '. ' + tip);
    var glyph = document.createElement('span');
    glyph.className = 'material-icons'; glyph.setAttribute('aria-hidden', 'true'); glyph.textContent = icon;
    element.appendChild(glyph);
    element.appendChild(document.createTextNode(label));
    return element;
  }
  function chips(view) {
    var list = [];
    if (view.configured) {
      list.push(chip('Key saved', 'key', 'ok', 'Saved' + (view.updatedBy ? ' by ' + view.updatedBy + ' on ' + when(view.updatedAt) : '') + '. The key is never shown again.'));
      if (view.healthCheckedAt == null) list.push(chip('Not tested', 'network_check', '', 'Use Test connection to check the key.'));
      else if (view.healthOk) list.push(chip('Test passed · ' + brief(view.healthCheckedAt), 'check_circle', 'ok', 'Last connection test: ' + when(view.healthCheckedAt)));
      else list.push(chip('Test failing', 'error', 'bad', words(view.healthError) + ' since ' + when(view.healthCheckedAt) + '.'));
    } else {
      list.push(chip('No key', 'key_off', 'warn', "Chat can't answer until a key is added."));
    }
    // Storage claims follow the server's active encryption mode (UAT #42).
    list.push(view.encrypted
      ? chip('Stored encrypted', 'lock', 'ok', 'The key is stored encrypted in the database.')
      : chip('Stored unencrypted', 'no_encryption', 'warn', 'Database encryption is off on this server, so the key is stored unencrypted, the same as SCM credentials.'));
    return list;
  }
  function layout() {
    var editing = !configured || replacing;
    el('key').hidden = !editing;
    el('save').hidden = !editing;
    el('replace').hidden = editing;
    el('test').hidden = !configured;
    el('remove').hidden = !configured;
  }
  function render(view) {
    version = view.version;
    configured = !!view.configured;
    replacing = false;
    el('state').replaceChildren.apply(el('state'), chips(view));
    el('key').supportingText = view.encrypted ? 'Stored encrypted and never shown again'
      : 'Never shown again; stored unencrypted because database encryption is off';
    el('key').label = configured ? 'New API key (replaces the saved one)' : 'API key';
    el('key').value = '';
    layout();
  }
  document.addEventListener('click', async function (event) {
    var d = dialog(); if (!d) return;
    try {
      if (event.target.closest('[data-ai-integration-open]')) { status(''); render(await api('')); await d.show(); return; }
      if (!d.contains(event.target)) return;
      if (event.target.closest('[data-ai-integration-close]')) { d.close(); return; }
      if (event.target.closest('[data-ai-integration-replace]')) { replacing = true; status(''); layout(); if (el('key').focus) el('key').focus(); return; }
      if (event.target.closest('[data-ai-integration-save]')) {
        var key = el('key').value.trim();
        if (!key) { status('Enter the API key to save.'); return; }
        render(await api('', {apiKey: key, version: version}));
        status('Key saved. Test the connection to check it.');
      } else if (event.target.closest('[data-ai-integration-test]')) {
        status('Testing…');
        var result = await api('/test', {});
        render(result.integration); status(result.message);
      } else if (event.target.closest('[data-ai-integration-remove]')) {
        if (!window.confirm('Remove the OpenAI API key? Chat stops answering until a new key is added.')) return;
        render(await api('/remove', {version: version}));
        status('Key removed.');
      }
    } catch (e) { el('key').value = ''; status(e.message); }
  });
})();

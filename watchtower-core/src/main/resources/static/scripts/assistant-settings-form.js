(function () {
  'use strict';
 if(window.watchtowerSettingsFormInstalled)return;window.watchtowerSettingsFormInstalled=true;
 function init(){
  // UAT #41 / board AiSettings2: typed assistant settings as outlined fields with their units. The
  // JSON editor stays the single source that the one Save sends; these fields read from it and write
  // back into it, scaled to stored units (bytes, microdollars). The Ready chip counts setup steps
  // from the stored settings and the AI integration.
  var root = document.querySelector('[data-assistant-admin]');
  var form = root && root.querySelector('[data-assistant-typed-settings]');
  var editor = root && root.querySelector('[data-assistant-settings]');
  if (!form || !editor || form.dataset.ready) return;
  form.dataset.ready = 'true';

  function read() {
    try { return JSON.parse(editor.value); } catch (e) { return null; }
  }
  function get(settings, path) {
    return path.split('.').reduce(function (value, key) { return value == null ? undefined : value[key]; }, settings);
  }
  function set(settings, path, value) {
    var keys = path.split('.');
    var target = keys.slice(0, -1).reduce(function (value, key) {
      if (value[key] == null || typeof value[key] !== 'object') value[key] = {};
      return value[key];
    }, settings);
    target[keys[keys.length - 1]] = value;
  }
  /** md-outlined-select takes md-select-option children; a native select takes option. */
  function option(select, value, label, selected) {
    var native = select.tagName === 'SELECT';
    var element = document.createElement(native ? 'option' : 'md-select-option');
    element.setAttribute('value', value);
    if (native) element.value = value;
    if (native) element.textContent = label;
    else { var headline = document.createElement('div'); headline.slot = 'headline'; headline.textContent = label; element.appendChild(headline); }
    if (selected) { element.setAttribute('selected', ''); element.selected = true; }
    select.appendChild(element);
  }
  function validity(input, message) { if (typeof input.setCustomValidity === 'function') input.setCustomValidity(message); }
  function minimum(input) { return Number(input.getAttribute('min') || 0); }

  var modelSelect = form.querySelector('[data-setting-model]');
  var effortSelect = form.querySelector('[data-setting-effort]');

  function fillEfforts(settings) {
    effortSelect.replaceChildren();
    var model = (settings.allowedModels || []).find(function (m) { return m.id === modelSelect.value; });
    (model ? model.efforts : []).forEach(function (effort) { option(effortSelect, effort, effort || 'default', effort === settings.defaultEffort); });
    effortSelect.value = settings.defaultEffort;
    showChoice(effortSelect);
  }

  /** Options arrive after the page's own select resync, so redraw the chosen value once they render. */
  function showChoice(select) {
    if (select.tagName === 'SELECT' || typeof select.reset !== 'function') return;
    var chosen = select.value;
    Promise.resolve(select.updateComplete).then(function () {
      select.reset();
      if (chosen && select.value !== chosen) select.value = chosen;
    });
  }

  function populate() {
    var settings = read();
    if (!settings) return;
    form.querySelectorAll('[data-setting]').forEach(function (input) {
      var stored = get(settings, input.dataset.setting);
      var scale = Number(input.dataset.scale) || 1;
      input.value = typeof stored === 'number' ? String(Math.round((stored / scale) * 100) / 100) : '';
      validity(input, '');
    });
    modelSelect.replaceChildren();
    var models = settings.allowedModels || [];
    if (!models.length) option(modelSelect, '', 'No approved model yet (Advanced › Approve a model)', true);
    models.forEach(function (m) { option(modelSelect, m.id, m.id, m.id === settings.defaultModel); });
    modelSelect.value = settings.defaultModel || '';
    showChoice(modelSelect);
    fillEfforts(settings);
    checklist(settings);
  }

  function write(input) {
    var settings = read();
    if (!settings) return;
    if (input === modelSelect) {
      settings.defaultModel = modelSelect.value;
      fillEfforts(settings);
      settings.defaultEffort = effortSelect.value;
    } else if (input === effortSelect) {
      settings.defaultEffort = effortSelect.value;
    } else {
      var number = Number(input.value);
      if (input.value === '' || !Number.isFinite(number) || number < minimum(input)) {
        validity(input, 'Enter a number of at least ' + minimum(input) + '.');
        if (typeof input.reportValidity === 'function') input.reportValidity();
        return;
      }
      validity(input, '');
      set(settings, input.dataset.setting, Math.round(number * (Number(input.dataset.scale) || 1)));
    }
    editor.value = JSON.stringify(settings, null, 2);
  }

  async function integration() {
    try {
      var response = await fetch('/admin/assistant/integrations/openai', {headers: {'Accept': 'application/json'}});
      return response.ok ? await response.json() : null;
    } catch (e) {
      return null;
    }
  }

  async function checklist(settings) {
    var list = root.querySelector('[data-assistant-checklist]');
    if (!list) return;
    var key = await integration();
    var models = settings.allowedModels || [];
    // [done, short label, hover text, word for the Ready chip when done]
    var items = [
      [key && key.configured && key.healthOk,
        key && key.configured ? (key.healthOk ? 'API key added and tested' : 'API key failing its test') : 'Add the OpenAI API key',
        key && key.configured && !key.healthOk ? 'Use Test connection under AI integration.' : 'Under AI integration.', 'key saved and connection healthy'],
      [models.length > 0, models.length > 0 ? models.length + (models.length === 1 ? ' approved model' : ' approved models') : 'Approve a model',
        'Under Limits › Advanced › Approve a model.', 'model approved'],
      [!!settings.defaultModel && models.some(function (m) { return m.id === settings.defaultModel; }),
        'Choose default model and effort', 'Under Limits › Conversations.', 'default model chosen'],
      [!!settings.enabled, settings.enabled ? 'Chat is on' : 'Run answer evaluation, then turn chat on',
        'Answer evaluation checks chat answers before everyone can use chat.', 'chat on']
    ];
    // A stepper with ticks, and the same count on the "Ready / Not ready" chip by the title.
    list.replaceChildren();
    items.forEach(function (item) {
      var li = document.createElement('li');
      li.className = 'wt-stepper__step' + (item[0] ? ' wt-stepper__step--done' : '');
      var icon = document.createElement('span');
      icon.className = 'material-icons';
      icon.setAttribute('aria-hidden', 'true');
      icon.textContent = item[0] ? 'check_circle' : 'radio_button_unchecked';
      li.appendChild(icon);
      var state = document.createElement('span');
      state.className = 'visually-hidden';
      state.textContent = item[0] ? 'Done: ' : 'To do: ';
      li.appendChild(state);
      li.appendChild(document.createTextNode(item[1]));
      li.dataset.tip = item[2];
      li.tabIndex = 0;
      list.appendChild(li);
    });
    readyChip(items);
  }

  function readyChip(items) {
    var chip = root.querySelector('[data-assistant-ready-chip]');
    if (!chip) return;
    var done = items.filter(function (item) { return item[0]; }), next = items.find(function (item) { return !item[0]; });
    var ready = !next;
    chip.hidden = false;
    chip.classList.toggle('wt-mini-chip--ok', ready);
    chip.classList.toggle('wt-mini-chip--warn', !ready);
    chip.querySelector('[data-assistant-ready-icon]').textContent = ready ? 'check_circle' : 'pending';
    chip.querySelector('[data-assistant-ready-label]').textContent = ready ? 'Ready' : 'Not ready';
    chip.dataset.tip = done.length + ' of ' + items.length + ' setup steps done' + (ready
      ? ': ' + done.map(function (item) { return item[3]; }).join(', ') + '.'
      : '. Next: ' + next[1] + ' (' + next[2] + ')');
    chip.setAttribute('aria-label', (ready ? 'Ready' : 'Not ready') + ': ' + chip.dataset.tip);
  }

  editor.addEventListener('wt:settings-loaded', populate);
  form.addEventListener('change', function (event) {
    if (event.target.matches('[data-setting], [data-setting-model], [data-setting-effort]')) write(event.target);
  });
  // Editing the JSON directly refreshes the fields when it is valid.
  editor.addEventListener('input', function () { if (read()) populate(); });
 }
 init();document.addEventListener('htmx:afterSwap',init);
})();

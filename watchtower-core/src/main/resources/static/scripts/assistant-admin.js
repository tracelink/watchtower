(function () {
  'use strict';
  // AI assistant settings: load the stored settings, the feature switches, the one Save, model
  // discovery, and the audit with repeats grouped and a failing-cleanup flag (board AiSettings2,
  // 2026-10-22). Every server value is rendered as text.
  var EVENTS = {
    AI_KEY_SAVED: ['API key saved', 'key', 'ok'], AI_KEY_REMOVED: ['API key removed', 'key_off', 'warn'],
    SETTINGS_CHANGED: ['Settings saved', 'tune', ''], CHAT_DISABLED: ['Chat turned off', 'toggle_off', ''],
    SUBMITTED: ['Question asked', 'chat', ''], STARTED: ['Answer started', 'play_arrow', ''],
    RECOVERED: ['Answer resumed', 'replay', ''], COMPLETED: ['Answered', 'check_circle', 'ok'],
    FAILED: ['Failed', 'error', 'bad'], TIMED_OUT: ['Timed out', 'error', 'bad'], CANCELED: ['Canceled', 'cancel', ''],
    REFUSED: ['Declined', 'block', 'warn'], INCOMPLETE: ['Incomplete', 'pending', 'warn'],
    LIMIT_REACHED: ['Limit reached', 'speed', 'warn'], TOOL_READ: ['Tool read', 'manage_search', ''],
    TOOL_REJECTED: ['Tool call refused', 'block', 'warn'], PROVIDER_ATTEMPT: ['Model request', 'send', ''],
    PROVIDER_RETRY: ['Model request retried', 'replay', 'warn'], OUTCOME_RECORDED: ['Outcome reported', 'rate_review', ''],
    AUDIT_TRANSCRIPT_VIEW: ['Transcript viewed', 'visibility', ''], DELETE_FAILED: ['Deletion failed', 'error', 'bad'],
    STORAGE_RECOVERY_REQUIRED: ['Storage needs recovery', 'error', 'bad'],
    RETENTION_FAILED: ['Retention failed', 'error', 'bad'], DRAFT_PREPARED: ['Change set prepared', 'rule', '']
  };
  var PROVIDERS = {OPENAI: 'OpenAI'};
  var TASKS = {UNDERSTAND_RULE: 'Understand a rule', RESOLVE_FINDING: 'Resolve a finding', REVIEW_CHANGE: 'Review a change'};
  var PAGE = 20;

  /** "PROVIDER_AUTHENTICATION" reads "Provider authentication": no internal codes on the page. */
  function words(code) {
    var text = String(code).toLowerCase().replace(/_/g, ' ');
    return text.charAt(0).toUpperCase() + text.slice(1);
  }
  function when(millis) {
    return window.WatchtowerTime ? window.WatchtowerTime.format(millis) : new Date(millis).toLocaleString(undefined, {timeZoneName: 'short'});
  }
  function brief(millis) {
    return window.WatchtowerTime && window.WatchtowerTime.short ? window.WatchtowerTime.short(millis) : when(millis);
  }
  function node(tag, className, text) {
    var element = document.createElement(tag);
    if (className) element.className = className;
    if (text !== undefined) element.textContent = text;
    return element;
  }
  function chip(label, icon, tone, tip) {
    var element = node('span', 'wt-mini-chip' + (tone ? ' wt-mini-chip--' + tone : ''));
    if (icon) { var glyph = node('span', 'material-icons', icon); glyph.setAttribute('aria-hidden', 'true'); element.appendChild(glyph); }
    element.appendChild(node('span', '', label));
    if (tip) { element.dataset.tip = tip; element.tabIndex = 0; }
    return element;
  }
  function dollars(micros) { return '$' + (Number(micros || 0) / 1000000).toFixed(2); }
  function table(headings, caption) {
    var wrap = node('div', 'wt-table-scroll'), grid = node('table', 'table mb-0 wt-setup-table'), head = node('tr');
    grid.appendChild(node('caption', 'visually-hidden', caption));
    headings.forEach(function (h) { var th = node('th', '', h); th.scope = 'col'; head.appendChild(th); });
    grid.appendChild(node('thead')).appendChild(head);
    var body = grid.appendChild(node('tbody'));
    wrap.appendChild(grid);
    return {wrap: wrap, body: body};
  }
  function cell(row, content) {
    var td = row.appendChild(node('td'));
    if (content instanceof Node) td.appendChild(content); else td.textContent = content;
    return td;
  }
  /** "STORAGE_RETENTION:20:S3Exception/AccessDenied/HTTP403" → count 20 and the sanitized code. */
  function retention(target) {
    var parts = String(target || '').split(':');
    return {count: /^\d+$/.test(parts[1] || '') ? Number(parts[1]) : 1, code: parts.slice(2).join(':')};
  }
  function versions(e) { return 'Prompt ' + e.prompt_version + ' · tools ' + e.tool_version; }
  function detail(e) {
    if (e.event === 'RETENTION_FAILED') {
      var failure = retention(e.target);
      return chip('Transcript cleanup', 'delete_forever', '', 'Storage retention could not expire transcripts' + (failure.code ? ' (' + failure.code + ')' : '') + '. ' + versions(e) + '.');
    }
    if (!e.target) return e.model ? chip(e.model + (e.effort ? ' · ' + e.effort : ''), 'smart_toy', '', versions(e)) : null;
    if (/^AI_KEY_/.test(e.event)) return chip(PROVIDERS[e.target] || words(e.target), 'hub', '', versions(e));
    if (e.event === 'SETTINGS_CHANGED') return chip('Version ' + e.target, 'history', '', versions(e));
    if (/^[A-Z][A-Z_]+$/.test(e.target)) return chip(words(e.target), 'info', '', versions(e));
    return chip(String(e.target).split(':')[0], 'build', '', String(e.target) + ' · ' + versions(e));
  }
  /** Consecutive identical events (same event, actor and detail) become one row with "× n". */
  function group(events) {
    var rows = [];
    events.forEach(function (e) {
      var key = [e.event, e.actor, e.event === 'RETENTION_FAILED' ? '' : e.target, e.model].join('|');
      var count = e.event === 'RETENTION_FAILED' ? retention(e.target).count : 1;
      var last = rows[rows.length - 1];
      if (last && last.key === key) { last.count += count; last.cost += Number(e.cost_micros || 0); last.oldest = e.created_at; }
      else rows.push({key: key, event: e, count: count, cost: Number(e.cost_micros || 0), oldest: e.created_at});
    });
    return rows;
  }
  function eventRow(body, row) {
    var e = row.event, tr = body.appendChild(node('tr')), known = EVENTS[e.event] || [words(e.event), 'radio_button_unchecked', ''];
    var time = node('span', '', brief(e.created_at)); time.tabIndex = 0;
    time.dataset.tip = when(e.created_at) + (row.count > 1 ? ' (' + row.count + ' times, ' + brief(row.oldest) + ' the earliest)' : '');
    cell(tr, time);
    cell(tr, chip(e.actor, e.actor === 'system' ? 'settings' : 'person'));
    var what = node('span', 'wt-meta-chips');
    what.appendChild(chip(known[0], known[1], known[2]));
    if (row.count > 1) what.appendChild(node('span', 'wt-count-badge wt-assistant-repeat', '× ' + row.count));
    cell(tr, what);
    cell(tr, detail(e) || '—');
    cell(tr, row.cost ? dollars(row.cost) : '—');
  }
  function sessionSize(s) {
    var turns = s.turn_count + (s.turn_count === 1 ? ' turn' : ' turns');
    if (Number(s.budget_blocked) > 0 && !Number(s.tokens))
      return chip(turns + ' · not sent: daily budget', 'savings', 'warn', 'The daily AI budget refused this question before any model request, so nothing was used or charged.');
    return chip(turns + ' · ' + Number(s.tokens).toLocaleString('en-US') + ' tokens · ' + dollars(s.cost_micros), 'chat', '', 'Tokens and cost recorded for this conversation.');
  }
  function sessionState(s) {
    if (s.transcript_purged_at) return chip('Purged', 'delete', '');
    if (s.expires_at <= Date.now()) return chip('Expired, deletion pending', 'schedule', 'warn');
    return chip('Until ' + brief(s.expires_at), 'schedule', '', 'Kept until ' + when(s.expires_at));
  }
  function sessionRow(body, s) {
    var row = body.appendChild(node('tr'));
    var started = node('span', '', brief(s.started_at)); started.dataset.tip = when(s.started_at); started.tabIndex = 0;
    cell(row, started);
    cell(row, chip(s.owner, 'person'));
    cell(row, sessionSize(s));
    cell(row, sessionState(s));
    var link = node('a', 'wt-icon-action');
    link.href = '/admin/assistant/transcripts/' + encodeURIComponent(s.session_id);
    link.setAttribute('aria-label', 'Open transcript ' + s.session_id.slice(0, 8));
    link.dataset.tip = 'Open transcript ' + s.session_id.slice(0, 8) + ' (viewing is audited)';
    var glyph = link.appendChild(node('span', 'material-icons', 'open_in_new')); glyph.setAttribute('aria-hidden', 'true');
    cell(row, link).className = 'text-end';
  }
  function card(title, count, extra) {
    var section = node('section', 'card card-small mb-3 wt-assistant-audit-card'), head = section.appendChild(node('div', 'wt-assistant-audit-head'));
    head.appendChild(node('h2', 'wt-section-title mb-0', title));
    if (count !== undefined) head.appendChild(node('span', 'wt-count-badge', String(count)));
    if (extra) head.appendChild(extra);
    return section;
  }
  function pager() {
    var nav = node('span', 'wt-assistant-audit-pager');
    nav.appendChild(chip('Repeats grouped', 'unfold_less'));
    [['prev', 'chevron_left', 'Newer activity'], ['next', 'chevron_right', 'Older activity']].forEach(function (b) {
      var button = node('button', 'wt-icon-action'); button.type = 'button'; button.setAttribute('data-assistant-audit-' + b[0], '');
      button.setAttribute('aria-label', b[2]); button.dataset.tip = b[2];
      var glyph = button.appendChild(node('span', 'material-icons', b[1])); glyph.setAttribute('aria-hidden', 'true');
      nav.appendChild(button);
    });
    return nav;
  }
  /** What to do about a failed cleanup: a denied S3 call is an AWS permission to grant, anything else is checked from the code. */
  function retentionAdvice(r) {
    var code = r.code ? ' (' + r.code + ')' : '';
    if (/AccessDenied|HTTP403/.test(r.code || '')) {
      return 'AWS refused the daily cleanup' + code + '. Ask whoever manages AWS to let the Watchtower role call s3:ListBucketVersions on the transcript bucket and s3:GetObjectVersionTagging and s3:PutObjectVersionTagging on its objects. The next daily run then clears this.';
    }
    return 'The daily storage-retention job could not tag expired transcripts' + code + '. Check that the transcript bucket has the Watchtower lifecycle rule and that the role can list object versions and read/write version tags; the next run then clears this.';
  }
  function retentionBanner(r) {
    var line = node('div', 'wt-failure-line mb-3'), glyph = line.appendChild(node('span', 'material-icons', 'error'));
    glyph.setAttribute('aria-hidden', 'true');
    line.appendChild(node('span', '', 'Transcript cleanup has failed ' + r.failures + (r.failures === 1 ? ' time' : ' times') + ' in the last day (last ' + brief(r.last_failed_at) + '). Expired chats are not being removed.'));
    line.appendChild(chip('What to do', 'info', '', retentionAdvice(r)));
    return line;
  }
  function renderAudit(area, data, offset) {
    area.replaceChildren();
    if (offset === 0 && data.retention) area.appendChild(retentionBanner(data.retention));
    var events = card('Events', undefined, pager()), sessions;
    if (data.events.length) {
      var grid = table(['When', 'Who', 'Event', 'Detail', 'Cost'], 'Assistant audit events, newest first, repeats grouped');
      group(data.events).forEach(function (row) { eventRow(grid.body, row); });
      events.appendChild(grid.wrap);
    } else events.appendChild(node('p', 'wt-field-help px-3', offset === 0 ? 'No assistant activity yet.' : 'No more activity.'));
    area.appendChild(events);
    if (data.sessions.length) {
      sessions = card('Conversations', data.sessions.length);
      var list = table(['Started', 'Who', 'Size', 'Kept until', ''], 'Assistant conversations and their transcripts');
      data.sessions.forEach(function (s) { sessionRow(list.body, s); });
      sessions.appendChild(list.wrap);
      area.appendChild(sessions);
    }
  }
  function retentionChip(root, r) {
    var flag = root.querySelector('[data-assistant-retention-chip]');
    if (!flag) return;
    flag.hidden = !r;
    if (r) { flag.dataset.tip = 'Storage retention could not run (' + r.failures + (r.failures === 1 ? ' failure' : ' failures') + ', last ' + when(r.last_failed_at) + '). ' + retentionAdvice(r); flag.setAttribute('aria-label', 'Transcript cleanup failing: ' + flag.dataset.tip); }
  }
  function usageToday(root, usage, settings) {
    var flag = root.querySelector('[data-assistant-usage-today]');
    if (!flag || !usage) return;
    flag.hidden = false;
    flag.replaceChildren();
    var glyph = flag.appendChild(node('span', 'material-icons', 'today')); glyph.setAttribute('aria-hidden', 'true');
    flag.appendChild(node('span', '', 'Today: ' + dollars(usage.org_cost_micros) + ' of ' + dollars(settings.orgDailyCostMicros) + ' for everyone'));
    flag.dataset.tip = 'Charged today (UTC), including requests reserved but not yet settled: everyone ' + Number(usage.org_tokens).toLocaleString('en-US') + ' of ' + Number(settings.orgDailyTokens || 0).toLocaleString('en-US') + ' tokens; you ' + Number(usage.user_tokens).toLocaleString('en-US') + ' tokens, ' + dollars(usage.user_cost_micros) + '.';
  }
  function renderOutcomes(area, outcomes) {
    area.replaceChildren();
    if (!outcomes.length) { area.appendChild(node('p', 'wt-field-help', 'No reported outcomes yet.')); return; }
    outcomes.forEach(function (o) {
      var number = function (v, unit) { return v == null ? 'unreported' : Number(v).toFixed(1) + unit; };
      var line = node('div', 'wt-meta-chips mb-2');
      line.appendChild(chip(TASKS[o.task_type] || 'Unspecified task', 'task_alt'));
      line.appendChild(chip(o.responses + (o.responses === 1 ? ' response' : ' responses'), 'forum'));
      line.appendChild(chip('rating ' + number(o.average_rating, ' / 5'), 'star'));
      line.appendChild(chip('average elapsed ' + number(o.average_elapsed_seconds == null ? null : o.average_elapsed_seconds / 60, ' min'), 'timer'));
      line.appendChild(chip('reported time saved ' + number(o.reported_saved_seconds == null ? null : o.reported_saved_seconds / 60, ' min'), 'savings'));
      area.appendChild(line);
    });
  }

  async function init() {
    var root = document.querySelector('[data-assistant-admin]');
    if (!root || root.dataset.ready || !root.querySelector('[data-assistant-admin-status]')) return;
    root.dataset.ready = 'true';
    var status = root.querySelector('[data-assistant-admin-status]'), editor = root.querySelector('[data-assistant-settings]'), version, offset = 0, knownSettings, settingsChanged = false;
    async function api(path, options) {
      options = options || {};
      options.headers = {'Content-Type': 'application/json'};
      if (options.method) options.headers[root.dataset.csrfHeader] = root.dataset.csrfToken;
      var res = await fetch('/admin/assistant' + path, options);
      if (!res.ok) throw new Error('Request failed (' + res.status + ').');
      return res.json();
    }
    function loaded(settings) { editor.value = JSON.stringify(settings, null, 2); editor.dispatchEvent(new Event('wt:settings-loaded')); }
    root.addEventListener('wt:assistant-model-approved', async function () {
      try {
        var fresh = await api('/settings'), saved = fresh.configuration.settings;
        var modelFields = ['allowedModels','defaultModel','defaultEffort'];
        if (knownSettings && Object.keys(saved).some(function (key) { return !modelFields.includes(key) && JSON.stringify(saved[key]) !== JSON.stringify(knownSettings[key]); })) {
          settingsChanged = true; status.textContent = 'Model approved, but other settings changed. Reload before saving your retained edits.'; return;
        }
        version = fresh.configuration.version;
        var draft; try { draft = JSON.parse(editor.value); } catch (ignored) { draft = fresh.configuration.settings; }
        ['allowedModels','defaultModel','defaultEffort'].forEach(function (key) { draft[key] = fresh.configuration.settings[key]; });
        knownSettings = JSON.parse(JSON.stringify(saved));
        loaded(draft); status.textContent = 'Model approved. Choose Chat activation for the initial testing group, then run answer evaluation.';
      } catch (e) { status.textContent = e.message; }
    });
    /**
     * Saves one part of the stored settings (prepare may refuse by throwing) and copies the saved
     * part into the unsaved draft, so other unsaved JSON edits stay in the editor.
     */
    async function saveOnly(prepare, copy) {
      var stored = await api('/settings'), next = stored.configuration.settings;
      prepare(next);
      await api('/settings', {method: 'POST', body: JSON.stringify({version: stored.configuration.version, settings: next})});
      var fresh = await api('/settings');
      version = fresh.configuration.version;
      knownSettings = JSON.parse(JSON.stringify(fresh.configuration.settings));
      try { var draft = JSON.parse(editor.value); copy(draft, fresh.configuration.settings); loaded(draft); } catch (ignored) { loaded(fresh.configuration.settings); }
      return {next: next, fresh: fresh};
    }
    function wire(selector, handler) {
      var control = root.querySelector(selector);
      if (!control) return null;
      control.addEventListener('change', async function () {
        var on = control.checked;
        try { status.textContent = await handler(on); } catch (e) { control.checked = !on; status.textContent = e.message; }
      });
      return control;
    }
    async function audit() {
      var area = root.querySelector('[data-assistant-audit]'), data = await api('/audit?offset=' + offset);
      renderAudit(area, data, offset);
      if (offset === 0) retentionChip(root, data.retention);
      var prev = root.querySelector('[data-assistant-audit-prev]'), next = root.querySelector('[data-assistant-audit-next]');
      if (prev) prev.disabled = offset === 0;
      if (next) next.disabled = data.events.length < PAGE && data.sessions.length < PAGE;
    }
    try {
      if (editor) {
        var cfg = await api('/settings');
        version = cfg.configuration.version;
        knownSettings = JSON.parse(JSON.stringify(cfg.configuration.settings));
        loaded(cfg.configuration.settings);
        // The Ready chip by the title shows readiness; no status sentence on load.
        usageToday(root, cfg.usage_today, cfg.configuration.settings);
        var settings = cfg.configuration.settings;
        // Chat on/off changes only "enabled" in the stored settings, never unsaved JSON edits.
        var toggle = wire('[data-assistant-enabled]', async function (on) {
          var result = await saveOnly(function (next) {
            next.enabled = on;
            if (on && !(next.allowedModels || []).length) throw new Error('Use Approve a model before turning chat on.');
          }, function (draft) { draft.enabled = on; });
          return (on ? 'Chat turned on. ' : 'Chat turned off. ') + result.fresh.readiness.message;
        });
        if (toggle) toggle.checked = !!settings.enabled;
        var actions = wire('[data-assistant-ruleset-actions]', async function (on) {
          await saveOnly(function (next) { next.rulesetActionsEnabled = on; }, function (draft) { draft.rulesetActionsEnabled = on; });
          return on ? 'Ruleset actions enabled. Chat and readiness are also required; each change set needs approval.' : 'Ruleset actions turned off.';
        });
        if (actions) actions.checked = !!settings.rulesetActionsEnabled;
        // R6: its own switch; it uses the chat default model, so a model must be chosen first.
        var assessing = wire('[data-assistant-finding-assessment]', async function (on) {
          var result = await saveOnly(function (next) {
            if (on && !(next.allowedModels || []).some(function (m) { return m.id === next.defaultModel && (m.efforts || []).includes(next.defaultEffort); }))
              throw new Error('Choose an allowed default model and effort before turning AI finding assessment on.');
            next.findingAssessment = {enabled: on};
          }, function (draft, saved) { draft.findingAssessment = saved.findingAssessment; });
          return on ? 'AI finding assessment turned on. It uses ' + result.next.defaultModel + ' and the daily chat budgets.' : 'AI finding assessment turned off.';
        });
        if (assessing) assessing.checked = !!(settings.findingAssessment || {}).enabled;
        // AI features beyond chat: one switch each, off by default. A feature that does its own work also
        // has a daily share (dollars) that caps it inside the organization's daily budget.
        root.querySelectorAll('[data-assistant-feature]').forEach(function (control) {
          var key = control.dataset.assistantFeature;
          var share = root.querySelector('[data-assistant-feature-share="' + key + '"]');
          var features = settings.features || {};
          control.checked = !!((features.enabled || {})[key]);
          if (share && (features.slices || {})[key]) share.value = String((features.slices[key].dailyCostMicros || 1000000) / 1000000);
          // The share is dollars; its token cap is the same fraction of the organization's token budget as
          // the dollars are of its cost budget, so neither cap is looser than the other.
          function sliceFor(org) {
            var dollars = Number(share && share.value);
            if (!(dollars >= 0.01)) throw new Error('Enter a daily share of at least $0.01.');
            var micros = Math.round(dollars * 1000000);
            var tokens = org.orgDailyCostMicros > 0 && org.orgDailyTokens > 0 ? Math.max(1, Math.round(micros * org.orgDailyTokens / org.orgDailyCostMicros)) : micros;
            return {dailyTokens: tokens, dailyCostMicros: micros};
          }
          async function save(on) {
            await saveOnly(function (next) {
              var current = next.features || {};
              var enabled = Object.assign({}, current.enabled || {}); enabled[key] = on;
              var slices = Object.assign({}, current.slices || {});
              if (share && on) slices[key] = sliceFor(next);
              next.features = {enabled: enabled, slices: slices};
            }, function (draft, saved) { draft.features = saved.features; });
          }
          control.addEventListener('change', async function () {
            var on = control.checked;
            try {
              await save(on);
              status.textContent = on ? 'Turned on. Chat must also be on; each person sees only what they may read.' : 'Turned off.';
            } catch (e) { control.checked = !on; status.textContent = e.message; }
          });
          if (share) share.addEventListener('change', async function () {
            if (!control.checked) return;
            try { await save(true); status.textContent = 'Daily share saved.'; } catch (e) { status.textContent = e.message; }
          });
        });
        // R5.2b: theme naming has its own switch and weekly budget; it changes only that setting.
        var naming = wire('[data-assistant-theme-naming]', async function (on) {
          var result = await saveOnly(function (next) {
            var current = next.themeNaming || {weeklyCostMicros: 10000000}, models = next.allowedModels || [];
            var choice = {model: current.model, effort: current.effort};
            if (on && !models.some(function (m) { return m.id === choice.model && (m.efforts || []).includes(choice.effort); })) {
              var fallback = models.find(function (m) { return m.id === next.defaultModel; }) || models[0];
              if (!fallback) throw new Error('Add an approved model to the settings before turning AI theme naming on.');
              choice = {model: fallback.id, effort: fallback.id === next.defaultModel && fallback.efforts.includes(next.defaultEffort) ? next.defaultEffort : fallback.efforts[0]};
            }
            next.themeNaming = Object.assign({}, current, choice, {enabled: on});
          }, function (draft, saved) { draft.themeNaming = saved.themeNaming; });
          var chosen = result.next.themeNaming;
          return on ? 'AI theme naming turned on with ' + chosen.model + ' and a weekly budget of $' + ((chosen.weeklyCostMicros || 0) / 1000000).toFixed(2) + '.' : 'AI theme naming turned off.';
        });
        if (naming) naming.checked = !!(settings.themeNaming || {}).enabled;
        root.querySelectorAll('[data-assistant-settings-save]').forEach(function (button) { button.addEventListener('click', async function () {
          try {
            if (settingsChanged) throw new Error('Other settings changed. Reload before saving your retained edits.');
            await api('/settings', {method: 'POST', body: JSON.stringify({version: version, settings: JSON.parse(editor.value)})});
            version++;
            knownSettings = JSON.parse(editor.value);
            status.textContent = 'Settings saved. Reload the page to update the assistant entry.';
            var dialog=button.closest('md-dialog');if(dialog&&typeof dialog.close==='function')await dialog.close();
          } catch (e) { status.textContent = e.message; }
        }); });
        root.querySelector('[data-assistant-discover]').addEventListener('click', async function () {
          // Discovered IDs fill the Model ID dropdown of Approve a model, not a status sentence.
          var dialog = document.getElementById('assistant-model-dialog');
          var discover = dialog && dialog.querySelector('[data-model-setup-discover]');
          if (!dialog || !discover) return;
          if (typeof dialog.show === 'function') await dialog.show(); else dialog.open = true;
          discover.click();
        });
      }
      if (root.querySelector('[data-assistant-audit]')) {
        await audit();
        // The pager is redrawn with each page, so listen on the audit area.
        root.querySelector('[data-assistant-audit]').addEventListener('click', function (event) {
          if (event.target.closest('[data-assistant-audit-prev]')) offset = Math.max(0, offset - PAGE);
          else if (event.target.closest('[data-assistant-audit-next]')) offset += PAGE;
          else return;
          audit().catch(function (e) { status.textContent = e.message; });
        });
      }
      var outcomes = root.querySelector('[data-assistant-outcomes]');
      if (outcomes) renderOutcomes(outcomes, await api('/outcomes'));
    } catch (e) { status.textContent = e.message; }
  }
  init();
  document.addEventListener('htmx:afterSwap', init);
})();
// Plan R6: agreement of advisory verdicts with human judgments made without seeing them. Three
// tiles, an empty state until there is a blind case, then the agree / disagree grid; the cases
// left out are chips (UAT walkthrough, 2026-10-16).
(function(){'use strict';
 function text(parent,tag,value){var el=document.createElement(tag);el.textContent=value;parent.appendChild(el);return el;}
 function set(d,name,value){var el=d.querySelector('[data-agreement-'+name+']');if(el)el.textContent=value;}
 async function show(){var d=document.querySelector('[data-assessment-agreement-dialog]');if(!d)return;var summary=d.querySelector('[data-assessment-agreement-summary]'),table=d.querySelector('[data-assessment-agreement-table]'),empty=d.querySelector('[data-assessment-agreement-empty]');
  try{var res=await fetch('/admin/assistant/assessment-agreement',{headers:{'Content-Type':'application/json'}});if(!res.ok)throw new Error('Agreement unavailable ('+res.status+').');var a=await res.json();
   summary.textContent=a.blind_cases?a.agreed+' of '+a.blind_cases+' blind cases agree ('+Math.round(a.agreement_rate*100)+'%). Left out: '+a.excluded_seen_before_judging+' judged after seeing the AI answer, '+a.excluded_no_human_judgment+' without a human judgment, '+a.excluded_needs_review_or_insufficient+' needs review or insufficient evidence.':'No blind cases yet: a finding needs an AI assessment and a human judgment made without seeing it.';
   set(d,'blind',String(a.blind_cases));set(d,'agreed',String(a.agreed));set(d,'rate',a.blind_cases?Math.round(a.agreement_rate*100)+'%':'—');
   set(d,'seen',a.excluded_seen_before_judging+' judged after seeing AI');set(d,'nohuman',a.excluded_no_human_judgment+' without a human');set(d,'review',a.excluded_needs_review_or_insufficient+' needs review');
   var body=table.querySelector('tbody');body.replaceChildren();table.hidden=!a.blind_cases;if(empty)empty.hidden=!!a.blind_cases;
   [['LIKELY_TRUE_POSITIVE','Likely true positive'],['LIKELY_FALSE_POSITIVE','Likely false positive']].forEach(function(row){var tr=text(body,'tr','');text(tr,'th',row[1]).scope='row';text(tr,'td',String(a.matrix[row[0]+'|TRUE_POSITIVE']||0));text(tr,'td',String(a.matrix[row[0]+'|FALSE_POSITIVE']||0));});
   var note=d.querySelector('[data-assessment-agreement-note]');if(note&&a.note)note.dataset.tip=a.note;
  }catch(e){summary.textContent=e.message;table.hidden=true;}
  await d.show();}
 document.addEventListener('click',function(e){if(e.target.closest('[data-assessment-agreement-open]'))show();if(e.target.closest('[data-assessment-agreement-close]'))document.querySelector('[data-assessment-agreement-dialog]').close();});
})();

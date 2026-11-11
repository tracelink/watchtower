const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
async function main() {
  const template = fs.readFileSync(path.join(resources, 'templates/assistant/admin.html'), 'utf8');
  const dom = new JSDOM(`<body>${template}</body>`, {url: 'https://watchtower.example/', runScripts: 'dangerously'});
  const w = dom.window;
  const root = w.document.querySelector('[data-assistant-admin]');
  Object.assign(root.dataset, {csrfHeader: 'X-CSRF-TOKEN', csrfToken: 'fixture'});
  root.querySelector('md-dialog').show = async () => {};
  root.querySelector('md-dialog').close = () => {};
  let saved;
  const saves = [];
  let stored = {version: 4, settings: {enabled: false, allowedModels: [], retentionDays: 14, turnCostMicros: 250000, maxInputBytes: 65536, orgDailyCostMicros: 20000000, orgDailyTokens: 2000000}};
  w.fetch = async (url, options = {}) => {
    let data;
    if (url.endsWith('/settings')) {
      if (options.method) { saved = {body: JSON.parse(options.body), headers: options.headers}; saves.push(saved.body); if (saved.body.settings.enabled || saved.body.settings.themeNaming || saved.body.settings.findingAssessment) stored = {version: stored.version + 1, settings: saved.body.settings}; }
      data = options.method ? {status: 'saved'} : {usage_today: {org_tokens: 900, org_cost_micros: 10000, user_tokens: 900, user_cost_micros: 10000}, configuration: stored, readiness: stored.settings.enabled ? {ready: false, problem: 'NO_API_KEY', message: 'No OpenAI API key is configured.'} : {ready: false, problem: 'CHAT_OFF', message: 'Chat is turned off.'}};
    } else if (url.includes('/audit')) data = {events: [{actor: '<img src=x>', event: 'TOOL_READ', created_at: Date.now(), model: 'fixture', effort: 'low', tokens: 200, cost_micros: 1000, prompt_version: 'r1-v1', tool_version: 'r1-v1'},
      {actor: 'system', event: 'RETENTION_FAILED', target: 'STORAGE_RETENTION:3:S3Exception/AccessDenied/HTTP403', created_at: 30, tokens: 0, cost_micros: 0, prompt_version: 'r1-v1', tool_version: 'r1-v1'},
      {actor: 'system', event: 'RETENTION_FAILED', target: 'STORAGE_RETENTION', created_at: 20, tokens: 0, cost_micros: 0, prompt_version: 'r1-v1', tool_version: 'r1-v1'},
      {actor: 'system', event: 'RETENTION_FAILED', target: 'STORAGE_RETENTION', created_at: 10, tokens: 0, cost_micros: 0, prompt_version: 'r1-v1', tool_version: 'r1-v1'}],
      sessions: [{owner: 'engineer', session_id: 'session', turn_count: 1, tokens: 0, cost_micros: 0, budget_blocked: 1, expires_at: 1}],
      retention: {failures: 5, last_failed_at: 30, code: 'S3Exception/AccessDenied/HTTP403'}};
    else if (url.endsWith('/assessment-agreement')) data = {blind_cases: 4, agreed: 3, agreement_rate: 0.75, matrix: {'LIKELY_FALSE_POSITIVE|FALSE_POSITIVE': 3, 'LIKELY_TRUE_POSITIVE|FALSE_POSITIVE': 1},
      excluded_seen_before_judging: 2, excluded_no_human_judgment: 5, excluded_needs_review_or_insufficient: 1, note: 'Counts only blind judgments.'};
    else if (url.endsWith('/outcomes')) data = [{task_type: 'UNDERSTAND_RULE', responses: 2, average_rating: 4, average_elapsed_seconds: 120, reported_saved_seconds: 180}];
    else data = {messages: [{role: 'user', text: '<script>alert(1)</script>'}], expiresAt: Date.now() + 86400000};
    return {ok: true, json: async () => data};
  };
  w.eval(fs.readFileSync(path.join(resources, 'static/scripts/assistant-settings-form.js'), 'utf8'));
  w.eval(fs.readFileSync(path.join(resources, 'static/scripts/assistant-admin.js'), 'utf8'));
  await new Promise(resolve => setTimeout(resolve, 0));
  await new Promise(resolve => setTimeout(resolve, 0));
  // UAT #41: typed fields show stored values in readable units and write back in stored units.
  const field = name => root.querySelector('[data-setting="' + name + '"]');
  const editor = root.querySelector('[data-assistant-settings]');
  assert.equal(field('retentionDays').value, '14');
  assert.equal(field('turnCostMicros').value, '0.25', 'microdollars are shown as dollars');
  assert.equal(field('maxInputBytes').value, '64', 'bytes are shown as KB');
  field('turnCostMicros').value = '0.5';
  field('turnCostMicros').dispatchEvent(new w.Event('change', {bubbles: true}));
  assert.equal(JSON.parse(editor.value).turnCostMicros, 500000);
  field('themeNaming.weeklyCostMicros').value = '12';
  field('themeNaming.weeklyCostMicros').dispatchEvent(new w.Event('change', {bubbles: true}));
  assert.equal(JSON.parse(editor.value).themeNaming.weeklyCostMicros, 12000000);
  assert.match(root.querySelector('[data-assistant-checklist]').textContent, /Add the OpenAI API key[\s\S]*Approve a model/);
  assert.equal(root.querySelectorAll('[data-assistant-checklist] .wt-stepper__step--done').length, 0, 'the stepper ticks only finished steps');
  const ready = root.querySelector('[data-assistant-ready-chip]');
  assert.equal(ready.hidden, false);
  assert.equal(ready.querySelector('[data-assistant-ready-label]').textContent, 'Not ready');
  assert.match(ready.dataset.tip, /^0 of 4 setup steps done\. Next: Add the OpenAI API key/);
  // Board AiSettings2: no readiness sentence under the tabs, one Save, no edit dialogs or banner card.
  assert.equal(root.querySelector('[data-assistant-admin-status]').textContent, '', 'no stray "Chat is ready." line');
  assert.equal(root.querySelectorAll('[data-assistant-settings-save]').length, 1, 'one Save');
  assert.equal(root.querySelector('#assistant-limits-dialog'), null);
  assert.equal(root.querySelector('[data-assistant-next-action]'), null, 'no setup banner card');
  assert.equal(root.querySelectorAll('md-outlined-text-field[data-setting]').length, 17, 'every numeric limit is an outlined field');
  assert.match(root.querySelector('[data-assistant-usage-today]').textContent, /Today: \$0\.01 of \$20\.00 for everyone/);
  const auditArea = root.querySelector('[data-assistant-audit]');
  assert.match(auditArea.textContent, /Retention failed× 5/, 'repeated retention failures are one row with the summed count');
  assert.equal(auditArea.querySelectorAll('tbody tr').length, 3, 'two events plus one conversation');
  assert.match(auditArea.querySelector('.wt-failure-line').textContent, /failed 5 times/);
  assert.equal(root.querySelector('[data-assistant-retention-chip]').hidden, false, 'header flags failing cleanup');
  const permissionTip = /s3:ListBucketVersions.*s3:GetObjectVersionTagging.*s3:PutObjectVersionTagging/;
  assert.match(auditArea.querySelector('.wt-failure-line [data-tip]').dataset.tip, permissionTip, 'an AccessDenied failure names the AWS permissions to grant');
  assert.match(root.querySelector('[data-assistant-retention-chip]').dataset.tip, permissionTip, 'and so does the header chip');
  assert.match(auditArea.textContent, /1 turn · not sent: daily budget/, 'a budget-refused chat does not read as 0 tokens');
  assert.doesNotMatch(auditArea.textContent, /STORAGE_RETENTION|r1-v1|AccessDenied/, 'codes only on hover');
  assert.equal(root.querySelector('[data-assistant-audit-prev]').disabled, true, 'no page before the first');
  assert.equal(root.querySelector('[data-assistant-audit-next]').disabled, true, 'a short page is the last page');
  assert.equal(root.querySelector('img'), null);
  assert.match(root.querySelector('[data-assistant-audit]').textContent, /Expired, deletion pending/);
  const auditText = root.querySelector('[data-assistant-audit]').textContent;
  assert.match(auditText, /Tool read/, 'events read in plain words');
  assert.doesNotMatch(auditText, /TOOL_READ/, 'no internal event codes');
  assert.equal(root.querySelectorAll('[data-assistant-audit] table').length, 2, 'events and conversations are tables');
  assert.match(root.querySelector('[data-assistant-outcomes]').textContent, /reported time saved 3.0 min/);
  root.querySelector('[data-assistant-settings-save]').click();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(saved.body.version, 4);
  assert.equal(saved.headers['X-CSRF-TOKEN'], 'fixture');
  const status = root.querySelector('[data-assistant-admin-status]');
  const toggle = root.querySelector('[data-assistant-enabled]');
  assert.equal(toggle.checked, false);
  // Turning chat on with no approved model is refused in the page and the control springs back.
  toggle.checked = true; toggle.dispatchEvent(new w.Event('change'));
  for (let i = 0; i < 4; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(toggle.checked, false);
  assert.match(status.textContent, /Use Approve a model/);
  const before = saves.length;
  stored = {version: 7, settings: {enabled: false, allowedModels: [{id: 'fixture'}], retentionDays: 14}};
  root.querySelector('[data-assistant-settings]').value = JSON.stringify({enabled: false, retentionDays: 3, allowedModels: [{id: 'fixture'}]});
  toggle.checked = true; toggle.dispatchEvent(new w.Event('change'));
  for (let i = 0; i < 6; i++) await new Promise(resolve => setTimeout(resolve, 0));
  const toggled = saves[before];
  assert.deepEqual(toggled, {version: 7, settings: {enabled: true, allowedModels: [{id: 'fixture'}], retentionDays: 14}}, 'only "enabled" changes; unsaved JSON edits are not saved by the toggle');
  assert.match(status.textContent, /Chat turned on\. No OpenAI API key is configured\./);
  assert.equal(JSON.parse(root.querySelector('[data-assistant-settings]').value).retentionDays, 3, 'unsaved JSON edits are kept in the editor');
  // R5.2b: AI theme naming has its own toggle; it picks the default model when none is chosen and changes nothing else.
  const naming = root.querySelector('[data-assistant-theme-naming]');
  assert.equal(naming.checked, false);
  stored = {version: 9, settings: {enabled: true, defaultModel: 'fixture', defaultEffort: 'low', allowedModels: [{id: 'fixture', efforts: ['low', 'high']}], retentionDays: 14}};
  const beforeNaming = saves.length;
  naming.checked = true; naming.dispatchEvent(new w.Event('change'));
  for (let i = 0; i < 6; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.deepEqual(saves[beforeNaming], {version: 9, settings: {enabled: true, defaultModel: 'fixture', defaultEffort: 'low', allowedModels: [{id: 'fixture', efforts: ['low', 'high']}], retentionDays: 14,
    themeNaming: {weeklyCostMicros: 10000000, model: 'fixture', effort: 'low', enabled: true}}});
  assert.match(status.textContent, /AI theme naming turned on with fixture and a weekly budget of \$10\.00\./);
  assert.equal(JSON.parse(root.querySelector('[data-assistant-settings]').value).themeNaming.enabled, true);
  stored = {version: 10, settings: {enabled: false, allowedModels: [], retentionDays: 14}};
  naming.checked = true; naming.dispatchEvent(new w.Event('change'));
  for (let i = 0; i < 4; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(naming.checked, false);
  assert.match(status.textContent, /Add an approved model to the settings before turning AI theme naming on/);
  // R6: the assessment switch needs an allowed default model, and changes only its own setting.
  const assessing = root.querySelector('[data-assistant-finding-assessment]');
  stored = {version: 11, settings: {enabled: false, defaultModel: 'gone', defaultEffort: 'low', allowedModels: [{id: 'fixture', efforts: ['low']}], retentionDays: 14}};
  assessing.checked = true; assessing.dispatchEvent(new w.Event('change'));
  for (let i = 0; i < 4; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(assessing.checked, false);
  assert.match(status.textContent, /Choose an allowed default model/);
  stored = {version: 12, settings: {enabled: false, defaultModel: 'fixture', defaultEffort: 'low', allowedModels: [{id: 'fixture', efforts: ['low']}], retentionDays: 14}};
  const beforeAssessing = saves.length;
  assessing.checked = true; assessing.dispatchEvent(new w.Event('change'));
  for (let i = 0; i < 6; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.deepEqual(saves[beforeAssessing].settings.findingAssessment, {enabled: true});
  assert.equal(saves[beforeAssessing].settings.enabled, false, 'chat stays as it was');
  assert.match(status.textContent, /AI finding assessment turned on\. It uses fixture and the daily chat budgets\./);
  // Page context: its own switch under "features"; it keeps the other features' switches and shares as stored.
  const cards = root.querySelector('[data-assistant-feature="contextCards"]');
  assert.ok(cards, 'a row for AI page context');
  assert.equal(cards.checked, false, 'off by default');
  stored = {version: 13, settings: {enabled: false, retentionDays: 14, features: {enabled: {batchTriage: true}, slices: {batchTriage: {dailyTokens: 100000, dailyCostMicros: 1000000}}}}};
  const beforeCards = saves.length;
  cards.checked = true; cards.dispatchEvent(new w.Event('change'));
  for (let i = 0; i < 6; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.deepEqual(saves[beforeCards].settings.features, {enabled: {batchTriage: true, contextCards: true}, slices: {batchTriage: {dailyTokens: 100000, dailyCostMicros: 1000000}}});
  assert.equal(saves[beforeCards].settings.enabled, false, 'chat stays as it was');
  assert.match(status.textContent, /Turned on\. Chat must also be on/);
  stored = {version: 14, settings: {enabled: false, retentionDays: 14, features: saves[beforeCards].settings.features}};
  cards.checked = false; cards.dispatchEvent(new w.Event('change'));
  for (let i = 0; i < 6; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(saves[saves.length - 1].settings.features.enabled.contextCards, false);
  // A feature with its own work: switch plus a dollar share that becomes its daily slice.
  const summary = root.querySelector('[data-assistant-feature="bypassSummary"]'), summaryShare = root.querySelector('[data-assistant-feature-share="bypassSummary"]');
  assert.ok(summary && summaryShare, 'a row with a switch and a daily share');
  assert.equal(summary.checked, false);
  stored = {version: 15, settings: {enabled: false, retentionDays: 14, orgDailyCostMicros: 20000000, orgDailyTokens: 2000000, features: {enabled: {contextCards: true}, slices: {}}}};
  summaryShare.value = '2.5';
  const beforeSummary = saves.length;
  summary.checked = true; summary.dispatchEvent(new w.Event('change'));
  for (let i = 0; i < 6; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.deepEqual(saves[beforeSummary].settings.features, {enabled: {contextCards: true, bypassSummary: true}, slices: {bypassSummary: {dailyTokens: 250000, dailyCostMicros: 2500000}}});
  stored = {version: 16, settings: {enabled: false, retentionDays: 14, orgDailyCostMicros: 20000000, orgDailyTokens: 2000000, features: saves[beforeSummary].settings.features}};
  summaryShare.value = '0'; summaryShare.dispatchEvent(new w.Event('change'));
  for (let i = 0; i < 4; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(status.textContent, /daily share of at least \$0\.01/);
  summaryShare.value = '4'; summaryShare.dispatchEvent(new w.Event('change'));
  for (let i = 0; i < 6; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(saves[saves.length - 1].settings.features.slices.bypassSummary.dailyCostMicros, 4000000);
  assert.equal(saves[saves.length - 1].settings.features.slices.bypassSummary.dailyTokens, 400000, 'the same share of the token budget as of the cost budget');
  assert.equal(saves[saves.length - 1].settings.features.enabled.bypassSummary, true, 'changing the share keeps it on');
  stored = {version: 17, settings: {enabled: false, retentionDays: 14, orgDailyCostMicros: 20000000, orgDailyTokens: 2000000, features: saves[saves.length - 1].settings.features}};
  summary.checked = false; summary.dispatchEvent(new w.Event('change'));
  for (let i = 0; i < 6; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(saves[saves.length - 1].settings.features.enabled.bypassSummary, false);
  const agreement = root.querySelector('[data-assessment-agreement-dialog]');
  agreement.show = async () => {};
  root.querySelector('[data-assessment-agreement-open]').click();
  for (let i = 0; i < 4; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(agreement.querySelector('[data-assessment-agreement-summary]').textContent, /3 of 4 blind cases agree \(75%\)\. Left out: 2 judged after seeing the AI answer/);
  assert.equal(agreement.querySelector('[data-agreement-blind]').textContent, '4');
  assert.equal(agreement.querySelector('[data-agreement-rate]').textContent, '75%');
  assert.equal(agreement.querySelector('[data-agreement-seen]').textContent, '2 judged after seeing AI');
  assert.equal(agreement.querySelector('[data-assessment-agreement-empty]').hidden, true, 'the grid replaces the empty state');
  assert.equal(agreement.querySelector('[data-assessment-agreement-note]').dataset.tip, 'Counts only blind judgments.');
  const cells = Array.from(agreement.querySelectorAll('tbody td')).map(td => td.textContent);
  assert.deepEqual(cells, ['0', '1', '0', '3']);
  // UAT #19: each expiring session links to its transcript page instead of opening a dialog.
  const link = root.querySelector('[data-assistant-audit] a');
  assert.equal(link.getAttribute('href'), '/admin/assistant/transcripts/session');
  assert.match(link.closest('tr').textContent, /Expired, deletion pending/);
  assert.equal(root.querySelector('[data-assistant-transcript]'), null);
  // Approving a model updates the shared version without discarding unrelated unsaved limits.
  const draft = JSON.parse(editor.value); draft.retentionDays = 8; editor.value = JSON.stringify(draft);
  stored = {version: 22, settings: {...stored.settings, defaultModel: 'new-model', defaultEffort: 'high', allowedModels: [{id:'new-model',efforts:['high']}]}};
  root.dispatchEvent(new w.Event('wt:assistant-model-approved'));
  for (let i = 0; i < 4; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(JSON.parse(editor.value).retentionDays, 8);
  assert.equal(JSON.parse(editor.value).defaultModel, 'new-model');
  root.querySelector('[data-assistant-settings-save]').click();
  for (let i = 0; i < 4; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(saved.body.version, 22, 'next save uses the model approval version');
  const beforeConflict = saves.length;
  stored = {version: 30, settings: {...stored.settings, retentionDays: 90, defaultModel:'concurrent-model'}};
  root.dispatchEvent(new w.Event('wt:assistant-model-approved'));
  for (let i = 0; i < 4; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(status.textContent, /other settings changed/i);
  root.querySelector('[data-assistant-settings-save]').click();
  for (let i = 0; i < 4; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(saves.length, beforeConflict, 'model refresh cannot silently overwrite a concurrent administrator change');
  dom.window.close();
  console.log('Assistant admin usage, version and transcript rendering tests passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});

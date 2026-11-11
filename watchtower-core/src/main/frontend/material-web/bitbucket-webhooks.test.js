const assert = require('node:assert/strict'), fs = require('node:fs'), path = require('node:path');
const { JSDOM } = require('jsdom');
const root = path.resolve(__dirname, '../../resources');
const template = fs.readFileSync(path.join(root, 'templates/configuration/bitbucketwebhooks.html'), 'utf8');
const script = fs.readFileSync(path.join(root, 'static/scripts/bitbucket-webhooks.js'), 'utf8');
const dom = new JSDOM(template, { runScripts: 'dangerously', url: 'https://wt.example/' }), w = dom.window;
const page = w.document.querySelector('[data-webhook-page]');
Object.assign(page.dataset, { endpoint: '/apisettings/bb/webhooks', label: 'bb', canModify: 'true', csrfHeader: 'X-CSRF-TOKEN', csrfToken: 'test-token' });
w.document.querySelectorAll('md-dialog').forEach(d => { d.show = () => d.setAttribute('open', ''); d.close = () => d.removeAttribute('open'); });
const ALL = ['pullrequest:created', 'pullrequest:updated', 'pullrequest:fulfilled', 'pullrequest:rejected', 'pullrequest:comment_created'];
const hook = (uuid, owned = true, events = ['pullrequest:created', 'pullrequest:updated']) =>
  ({ uuid, urlHostPath: 'wt.example/<img src=x onerror=alert(1)>', events, active: true, owned, secretSet: true });
const scope = (name, hooks, error = null) => ({ scope: name, hooks, checkedAt: Date.now() - 4 * 60000, stale: false, error });
const operation = { id: 'op1', jobId: 1, action: 'SYNC', status: 'PARTIAL_FAILURE', createdAt: Date.now() - 2 * 3600000, actor: 'alice', total: 3, finished: 3, failed: 1 };
const inventory = {
  workspace: scope('', [hook('workspace-id', true, ALL)]),
  repositories: [scope('payments', [hook('repo-id'), hook('foreign-id', false, ['pullrequest:created', 'pullrequest:comment_created', 'repo:push'])]), scope('restricted', [], 'MISSING_WEBHOOK_PERMISSION')],
  total: 2, ownedRepositoryHookCount: 1, rotation: { pending: false }, operations: [operation]
};
const calls = [];
w.fetch = async (url, options = {}) => {
  calls.push({ url, options });
  let body = inventory;
  if (url.endsWith('/workspace/live')) body = inventory.workspace.hooks;
  else if (url.includes('/repos/') && url.endsWith('/live')) body = inventory.repositories[0].hooks;
  else if (url.includes('/jobs/op1?')) body = { action: 'SYNC', status: 'PARTIAL_FAILURE', total: 3, finished: 3, failed: 1, tasks: [{ scope: '', status: 'DONE', result: 'CHECKED' }, { scope: 'restricted', status: 'FAILED', result: 'MISSING_WEBHOOK_PERMISSION' }] };
  else if (url.includes('/repositories?')) body = url.includes('page=1') ? { content: [{ slug: 'other', paused: true }], last: true } : { content: [{ slug: 'payments', paused: false }], last: false };
  else if (options.method && options.method !== 'GET') body = { operationId: 'operation-id' };
  return { ok: true, json: async () => body };
};
const settle = () => new Promise(r => setImmediate(r));
const $ = s => w.document.querySelector(s);
const text = s => $(s).textContent;
(async () => {
  w.eval(script); await settle();

  // Safe rendering: remote metadata is text, never HTML; the page has no explanatory paragraphs.
  assert.equal(w.document.querySelectorAll('img').length, 0, 'remote URL metadata is text, never HTML');
  assert.equal(w.document.querySelectorAll('[data-webhook-page] > p').length, 1, 'only the hidden status line is a paragraph');
  assert.equal($('[data-webhook-status]').hidden, true, 'no status text until there is something to say');

  // Workspace is its own slim row, never a repository row.
  assert.match(text('[data-workspace-hooks]'), /Workspace/);
  assert.equal($('[data-repo-hooks]').textContent.includes('workspace-id'), false, 'workspace never enters the repo table');
  assert.equal(w.document.querySelectorAll('[data-workspace-hooks] .wt-webhook-ws').length, 1);

  // Chips carry the status; hover text carries the detail.
  const chips = text('[data-webhook-chips]');
  assert.match(chips, /Workspace \+ 1 repo/);
  assert.match(chips, /Duplicate coverage/, 'active workspace plus repository hooks warn once, in a chip');
  assert.match(chips, /Activity 1/);
  assert.ok($('[data-webhook-chips] .wt-dot--setup'), 'a failed latest operation marks the Activity chip');
  assert.equal($('[data-webhook-chips] [data-activity-open]').getAttribute('data-tip'), 'Recent refreshes and changes');

  // Events read as preset chips; a foreign hook with other events says how many.
  const rows = $('[data-repo-hooks]').textContent;
  assert.match(rows, /Scan only/);
  assert.match(rows, /3 events/);
  assert.match(rows, /No permission/);
  assert.match(rows, /Also on workspace/);
  assert.equal(w.document.querySelectorAll('[data-repo-hooks] [data-tip="Foreign hook · read only"]').length, 1, 'foreign hook shows a lock, not actions');
  assert.equal($('[data-repo-hooks]').querySelectorAll('button[aria-label^="Edit"]').length, 1, 'foreign hook has no edit action');
  assert.equal(text('[data-repo-page-label]'), '1–2 of 2');

  // Pause: a hook on an exact preset is paused in place, keeping its events.
  $('[data-repo-hooks] button[aria-label^="Pause"]').click(); await settle(); await settle();
  const pause = calls.find(c => c.url.endsWith('/repos/payments/repo-id') && c.options.method === 'PATCH');
  assert.ok(pause); assert.deepEqual(JSON.parse(pause.options.body), { preset: 'SCAN_ONLY', active: false, uuid: 'repo-id' });
  assert.equal(pause.options.headers['X-CSRF-TOKEN'], 'test-token');

  // Paged selection across pages, one bulk request, CSRF header.
  $('[data-webhook-choose]').click(); await settle(); $('[data-picker-list] input').click();
  assert.match(text('[data-picker-list]'), /payments/);
  $('[data-picker-next]').click(); await settle();
  assert.match(text('[data-picker-list]'), /Scanning paused/);
  $('[data-picker-list] input').click();
  assert.equal(text('[data-picker-count]'), '2 selected');
  $('[data-picker-save]').click(); await settle(); await settle();
  const bulk = calls.find(c => c.url.endsWith('/repos') && c.options.method === 'POST');
  assert.ok(bulk); assert.deepEqual(JSON.parse(bulk.options.body).repositories, ['other', 'payments']);
  assert.equal(JSON.parse(bulk.options.body).preset, 'ALL');
  assert.equal(bulk.options.headers['X-CSRF-TOKEN'], 'test-token');

  // Workspace edit reads the live hook first, then saves the chosen preset.
  $('[data-workspace-hooks] button[aria-label^="Edit"]').click(); await settle();
  assert.equal(page.querySelector('input[name="preset"]:checked').value, 'ALL', 'dialog starts on the hook’s current preset');
  page.querySelector('input[name="preset"][value="SCAN_ONLY"]').checked = true; $('[data-settings-active]').checked = false;
  $('[data-settings-save]').click(); await settle(); await settle();
  const workspace = calls.find(c => c.url.endsWith('/workspace') && c.options.method === 'PUT');
  assert.equal(JSON.parse(workspace.options.body).active, false); assert.equal(JSON.parse(workspace.options.body).preset, 'SCAN_ONLY');

  // Activity: one list, then one operation's results, with plain wording.
  $('[data-activity-open]').click();
  assert.match(text('[data-activity-list]'), /Refresh/); assert.match(text('[data-activity-list]'), /alice/); assert.match(text('[data-activity-list]'), /1 failed/);
  $('[data-activity-list] button[aria-label="View results"]').click(); await settle();
  assert.equal($('[data-activity-detail]').hidden, false); assert.equal($('[data-activity-list]').hidden, true);
  assert.match(text('[data-outcome-list]'), /restricted — No permission/);
  assert.match(text('[data-outcome-list]'), /Workspace — Checked/);
  $('[data-outcome-back]').click(); assert.equal($('[data-activity-list]').hidden, false);

  // Rotation needs the typed label.
  $('[data-webhook-rotate]').click(); assert.equal($('[data-rotation-start]').disabled, true);
  $('[data-rotation-confirmation]').value = 'bb'; $('[data-rotation-confirmation]').dispatchEvent(new w.Event('input'));
  assert.equal($('[data-rotation-start]').disabled, false); $('[data-rotation-start]').click(); await settle(); await settle();
  assert.ok(calls.find(c => c.url.endsWith('/rotate-secret') && JSON.parse(c.options.body).confirmLabel === 'bb'));

  // Navigating back into the page must not wire it twice.
  const before = calls.length; w.document.dispatchEvent(new w.Event('htmx:afterSwap')); await settle();
  assert.equal(calls.length, before, 'htmx does not wire the page twice');
  w.close(); console.log('Webhooks: slim workspace row, preset chips, status chips, activity dialog, pause, paged selection, CSRF and rotation passed');
})().catch(e => { console.error(e); w.close(); process.exitCode = 1; });

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
const container = fs.readFileSync(path.join(resources, 'templates/fragments/container.html'), 'utf8');
const drawer = container.match(/<wt-assistant-drawer[\s\S]*?<\/wt-assistant-drawer>/)[0];
const helperScript = fs.readFileSync(path.join(resources, 'static/scripts/ai-helpers.js'), 'utf8');
const reviewScript = fs.readFileSync(path.join(resources, 'static/scripts/alert-change-set.js'), 'utf8');
const tick = (ms = 10) => new Promise(resolve => setTimeout(resolve, ms));
const ID = 'a1b2c3d4-0000-4000-8000-000000000001';

const route = (over = {}) => ({routeId: 7, version: 3, alertType: 'SECRET_DETECTED', channelId: 1, channelName: 'platform', channelEnabled: true, enabled: true, minPriority: 'MEDIUM',
  apiLabelFilter: null, repoInclude: null, repoExclude: null, aggregation: 'PER_SCAN', dedupeWindowHours: 720, ...over});
const changes = () => [
  {type: 'ADD', before: null, after: route({routeId: null, alertType: 'SECRET_LIVE', channelId: 2, channelName: 'appsec', minPriority: null})},
  {type: 'UPDATE', before: route(), after: route({minPriority: 'HIGH'})},
  {type: 'REMOVE', before: route({routeId: 9, alertType: 'SCM_REVIEW_ACTION_FAILED', channelName: 'appsec', minPriority: null, aggregation: 'PER_FINDING'}), after: null}];

function mockFetch(w, routes, calls) {
  w.fetch = async (url, options = {}) => {
    calls.push({url, method: options.method || 'GET', body: options.body, headers: options.headers});
    if (url === '/assistant/helpers') return {ok: true, status: 200, json: async () => ({alerts: true})};
    const answer = routes[(options.method || 'GET') + ' ' + url];
    if (!answer) return {ok: false, status: 404, json: async () => ({error: 'no route ' + url})};
    const reply = typeof answer === 'function' ? answer(options) : answer;
    const failed = reply.body !== undefined && reply.status >= 400;
    return {ok: !failed, status: failed ? reply.status : 200, json: async () => reply.body === undefined ? reply : reply.body};
  };
}

async function dialogPage(routes) {
  const body = `${drawer}<span data-ai-helper="alerts" hidden><button type="button" aria-label="Draft route changes">x</button></span>
   <div id="alertCopilotDialog"><textarea data-alert-copilot-text></textarea>
    <button type="button" data-alert-copilot-example data-text="Send secret detections to appsec">a</button><button type="button" data-alert-copilot-example data-text="Stop alerts about bypass requests">b</button>
    <div data-alert-copilot-result></div><span data-alert-copilot-approval hidden>approval</span>
    <button type="button" data-alert-copilot-close>Close</button><button type="button" data-alert-copilot-draft>Draft changes</button><a href="#" hidden data-alert-copilot-review>Review change set</a></div>`;
  const dom = new JSDOM(`<body>${body}</body>`, {url: 'https://watchtower.example/alertsettings', runScripts: 'dangerously', pretendToBeVisual: true});
  const w = dom.window, calls = [];
  mockFetch(w, routes, calls);
  const dialog = w.document.getElementById('alertCopilotDialog'); const log = {shown: 0, closed: 0};
  dialog.show = () => { log.shown++; }; dialog.close = () => { log.closed++; };
  w.eval(helperScript);
  const d = w.document.querySelector('wt-assistant-drawer'); d.dataset.csrfHeader = 'X-CSRF-TOKEN'; d.dataset.csrfToken = 'fixture';
  await tick(); await tick();
  return {w, calls, document: w.document, dialog, log, close: () => w.close()};
}

async function reviewPage(routes, expiresAt) {
  const body = `<section data-alert-change-set data-id="${ID}" data-csrf-header="X-CSRF-TOKEN" data-csrf-token="fixture">
   <div data-ac-chips><span id="fixed">Drafted by the assistant</span></div><table><tbody data-ac-rows></tbody></table><p data-ac-status></p>
   <button data-ac-apply disabled>Approve</button><button data-ac-cancel disabled>Cancel</button><button data-ac-refresh disabled>Refresh</button><a data-ac-back hidden href="/alertsettings?tab=routes">Back</a></section>`;
  const dom = new JSDOM(`<body>${body}</body>`, {url: 'https://watchtower.example/assistant/alert-changes/' + ID + '/review', runScripts: 'dangerously', pretendToBeVisual: true});
  const w = dom.window, calls = [];
  mockFetch(w, routes, calls);
  w.eval(helperScript); w.eval(reviewScript);
  await tick(); await tick();
  return {w, calls, document: w.document, close: () => w.close()};
}
const view = (over = {}) => ({id: ID, version: 0, status: 'DRAFT', contentHash: 'h1', expiresAt: Date.now() + 28 * 60000, preview: {changes: changes()}, receipt: null, ...over});

async function main() {
  // The icon opens the dialog; examples fill the sentence.
  const okDraft = {state: 'OK', changeSetId: ID, reviewUrl: '/assistant/alert-changes/' + ID + '/review', expiresAt: Date.now() + 1800000, changes: changes()};
  let p = await dialogPage({'POST /assistant/alert-copilot': okDraft});
  const anchor = p.document.querySelector('[data-ai-helper="alerts"]'), field = p.document.querySelector('[data-alert-copilot-text]');
  assert.equal(anchor.hidden, false, 'shown when the server says it will work');
  anchor.querySelector('button').click(); assert.equal(p.log.shown, 1);
  p.document.querySelectorAll('[data-alert-copilot-example]')[0].click(); assert.equal(field.value, 'Send secret detections to appsec');
  // An empty sentence is not sent.
  field.value = ''; p.document.querySelector('[data-alert-copilot-draft]').click(); await tick();
  assert.equal(p.calls.filter(c => c.method === 'POST').length, 0); assert.match(p.document.querySelector('[data-alert-copilot-result]').textContent, /in your own words/);
  // A draft shows Add, Change (before to after) and Remove, then offers the review page.
  field.value = 'Send secret alerts to appsec at High and above'; p.document.querySelector('[data-alert-copilot-draft]').click(); await tick();
  const result = p.document.querySelector('[data-alert-copilot-result]'), review = p.document.querySelector('[data-alert-copilot-review]');
  assert.match(result.textContent, /3 changes drafted/); assert.match(result.textContent, /Channels are never changed/);
  const rows = result.querySelectorAll('.wt-ai-change'); assert.equal(rows.length, 3);
  assert.match(rows[0].textContent, /Add.*Secret live.*appsec.*1 per scan/); assert.match(rows[1].textContent, /Change.*Secret detected.*platform.*Medium and above.*High and above/); assert.match(rows[2].textContent, /Remove.*Scm review action failed.*appsec/);
  assert.equal(review.hidden, false); assert.equal(review.getAttribute('href'), okDraft.reviewUrl);
  assert.equal(p.document.querySelector('[data-alert-copilot-approval]').hidden, false); assert.equal(p.document.querySelector('[data-alert-copilot-draft]').hidden, true);
  const post = p.calls.find(c => c.method === 'POST'); assert.equal(JSON.parse(post.body).text, 'Send secret alerts to appsec at High and above'); assert.equal(post.headers['X-CSRF-TOKEN'], 'fixture');
  // Changing the sentence makes the draft stale, so the button to ask again comes back.
  field.value = 'something else'; field.dispatchEvent(new p.w.Event('input')); assert.equal(review.hidden, true); assert.equal(p.document.querySelector('[data-alert-copilot-draft]').hidden, false);
  p.close();

  // A link that is not a review page is never used; refusals and limits read as notes.
  p = await dialogPage({'POST /assistant/alert-copilot': {...okDraft, reviewUrl: 'https://evil.example/x'}});
  p.document.querySelector('[data-alert-copilot-text]').value = 'x'; p.document.querySelector('[data-alert-copilot-draft]').click(); await tick();
  assert.equal(p.document.querySelector('[data-alert-copilot-review]').hidden, true); p.close();
  p = await dialogPage({'POST /assistant/alert-copilot': {state: 'REFUSED_SECRET', message: 'That text looks like it contains a secret, so it was not sent.'}});
  p.document.querySelector('[data-alert-copilot-text]').value = 'x'; p.document.querySelector('[data-alert-copilot-draft]').click(); await tick();
  assert.ok(p.document.querySelector('.wt-ai-note--bad'), 'a red lock note'); assert.match(p.document.querySelector('[data-alert-copilot-result]').textContent, /contains a secret/); p.close();
  p = await dialogPage({'POST /assistant/alert-copilot': {state: 'NOTHING', message: 'Those routes already exist, so there is nothing to change.'}});
  p.document.querySelector('[data-alert-copilot-text]').value = 'x'; p.document.querySelector('[data-alert-copilot-draft]').click(); await tick();
  assert.match(p.document.querySelector('[data-alert-copilot-result]').textContent, /nothing to change/); assert.equal(p.document.querySelector('[data-alert-copilot-review]').hidden, true); p.close();
  p = await dialogPage({'POST /assistant/alert-copilot': {status: 429, body: {error: 'The daily AI budget for alert-route copilot is used up; try again tomorrow.'}}});
  p.document.querySelector('[data-alert-copilot-text]').value = 'x'; p.document.querySelector('[data-alert-copilot-draft]').click(); await tick();
  assert.match(p.document.querySelector('[data-alert-copilot-result]').textContent, /budget .* used up/); assert.ok(p.document.querySelector('.wt-ai-note--warn')); p.close();

  // Review page: the table, the expiry chip, approve, and the receipt.
  const applied = view({version: 1, status: 'APPLIED', receipt: {actor: 'casey', appliedAt: Date.now(), added: 1, changed: 1, removed: 1}});
  p = await reviewPage({['GET /assistant/alert-changes/' + ID]: view(), ['POST /assistant/alert-changes/' + ID + '/apply']: applied});
  assert.equal(p.document.querySelectorAll('[data-ac-rows] tr').length, 3);
  assert.match(p.document.querySelector('[data-ac-rows] tr:nth-child(2)').textContent, /Change.*Secret detected.*Medium and above.*High and above/);
  assert.match(p.document.querySelector('[data-ac-rows] tr:nth-child(3)').textContent, /Route removed/); assert.match(p.document.querySelector('[data-ac-rows] tr:nth-child(1)').textContent, /No route/);
  assert.match(p.document.querySelector('[data-ac-chips]').textContent, /Expires in 28 min/); assert.equal(p.document.querySelector('[data-ac-apply]').disabled, false);
  p.document.querySelector('[data-ac-apply]').click(); await tick();
  const apply = p.calls.find(c => c.url.endsWith('/apply')); assert.deepEqual(JSON.parse(apply.body), {version: 0, contentHash: 'h1'}); assert.equal(apply.headers['X-CSRF-TOKEN'], 'fixture');
  assert.match(p.document.querySelector('[data-ac-chips]').textContent, /Applied by casey/); assert.equal(p.document.querySelector('[data-ac-back]').hidden, false); assert.equal(p.document.querySelector('[data-ac-apply]').hidden, true);
  p.close();

  // Routes changed since the draft: Approve stays off, refresh is refused, and the way back to the routes appears.
  p = await reviewPage({['GET /assistant/alert-changes/' + ID]: view(), ['POST /assistant/alert-changes/' + ID + '/apply']: {status: 409, body: {code: 'STALE_STATE', error: 'Routes changed since this draft. Refresh the preview, check it, and approve again.'}},
    ['POST /assistant/alert-changes/' + ID + '/refresh']: {status: 409, body: {code: 'STALE_STATE', error: 'A route this draft changes was edited or removed. Ask for the change again.'}}});
  p.document.querySelector('[data-ac-apply]').click(); await tick();
  assert.match(p.document.querySelector('[data-ac-chips]').textContent, /Routes changed since this draft/); assert.equal(p.document.querySelector('[data-ac-apply]').disabled, true); assert.equal(p.document.querySelector('[data-ac-refresh]').disabled, false);
  p.document.querySelector('[data-ac-refresh]').click(); await tick();
  assert.match(p.document.querySelector('[data-ac-status]').textContent, /Ask for the change again/); assert.equal(p.document.querySelector('[data-ac-back]').hidden, false); p.close();

  // An expired approval cannot be applied; cancel works; a canceled draft shows as canceled.
  p = await reviewPage({['GET /assistant/alert-changes/' + ID]: view({expiresAt: Date.now() - 1000})});
  assert.match(p.document.querySelector('[data-ac-chips]').textContent, /Approval expired/); assert.equal(p.document.querySelector('[data-ac-apply]').disabled, true); assert.equal(p.document.querySelector('[data-ac-refresh]').disabled, false); p.close();
  p = await reviewPage({['GET /assistant/alert-changes/' + ID]: view(), ['POST /assistant/alert-changes/' + ID + '/cancel']: view({status: 'CANCELED', version: 1})});
  p.document.querySelector('[data-ac-cancel]').click(); await tick();
  assert.match(p.document.querySelector('[data-ac-chips]').textContent, /Canceled/); assert.equal(p.document.querySelector('[data-ac-back]').hidden, false); p.close();
  console.log('Alert copilot: draft dialog and review page tests passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});

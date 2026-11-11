const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const resources = path.resolve(__dirname, '../../resources');
const helpers = fs.readFileSync(path.join(resources, 'static/scripts/ai-helpers.js'), 'utf8');
const review = fs.readFileSync(path.join(resources, 'static/scripts/ai-review.js'), 'utf8');
const template = fs.readFileSync(path.join(resources, 'templates/fragments/findings.html'), 'utf8');

// The real markup of the button, the chip and both dialogs, so the script and the template cannot drift apart.
const grab = (pattern) => { const match = template.match(pattern); assert.ok(match, 'missing in findings.html: ' + pattern); return match[0]; };
const BUTTON = grab(/<md-outlined-button[^>]*data-ai-helper="aiReview"[\s\S]*?<\/md-outlined-button>/);
const CHIP = grab(/<button[^>]*data-ai-review-chip[\s\S]*?<\/button>/);
const PICK = grab(/<md-dialog data-ai-review-pick[^>]*>[\s\S]*?<\/md-dialog>/);
const RESULTS = grab(/<md-dialog data-ai-review-results>[\s\S]*?<\/md-dialog>/);

const page = (scanType) => `<!doctype html><body>
  <wt-assistant-drawer data-csrf-header="X-CSRF-TOKEN" data-csrf-token="fixture"></wt-assistant-drawer>
  <div data-scan-type="${scanType}" data-scan-id="7"></div>
  <section data-finding-workspace>${BUTTON}${CHIP}${PICK}${RESULTS}</section></body>`;

function ok(body) { return {ok: true, status: 200, json: async () => body}; }
function fail(status, body) { return {ok: false, status, json: async () => body}; }
const settle = () => new Promise((resolve) => setTimeout(resolve, 20));
const DRAFT = '5d1c5a0e-0000-4000-8000-000000000001';

const point = (n, extra = {}) => Object.assign({id: 'i' + n, path: 'src/Dao.java', first_line: 10 * n, last_line: 10 * n + 1, cwe: 'CWE-89', cwe_name: 'SQL Injection',
  rationale: 'Input is added to a query.', confidence: 'high', scanner: 'pmd', coverage: 'GAP', covered_by: null, state: 'OPEN', can_draft: true}, extra);
const run = (state, items = [], extra = {}) => Object.assign({run_id: 'r1', state, files_total: 2, files_done: state === 'DONE' ? 2 : 1, items_total: items.length,
  files: [{path: 'src/Dao.java', status: 'DONE', note: null}], items, note: 'Advice only.'}, extra);

async function load(scanType, flags, respond) {
  const dom = new JSDOM(page(scanType), {runScripts: 'dangerously', url: 'https://watchtower.example/pull-requests/7'});
  const w = dom.window;
  const calls = [];
  const timers = [];
  w.HTMLElement.prototype.show = function () { this.open = true; };
  w.HTMLElement.prototype.close = function () { this.open = false; };
  w.fetch = async (url, options = {}) => {
    const call = {url, method: options.method || 'GET', headers: options.headers || {}, body: options.body ? JSON.parse(options.body) : null};
    calls.push(call);
    if (url === '/assistant/helpers') return ok(flags);
    return respond(call);
  };
  w.setTimeout = (fn, ms) => { timers.push({fn, ms}); return timers.length; };
  w.clearTimeout = () => {};
  w.eval(review);
  w.eval(helpers);
  w.document.dispatchEvent(new w.Event('DOMContentLoaded'));
  await settle();
  const q = (selector) => w.document.querySelector(selector);
  const all = (selector) => Array.from(w.document.querySelectorAll(selector));
  return {w, calls, timers, q, all};
}

async function main() {
  // Not offered to someone who cannot use it, nor on other kinds of scan.
  const off = await load('pull_request', {aiReview: false}, () => ok({state: 'NONE'}));
  assert.equal(off.q('[data-ai-helper="aiReview"]'), null);
  const upload = await load('upload', {aiReview: true}, () => ok({state: 'NONE'}));
  assert.equal(upload.q('[data-ai-helper="aiReview"]'), null, 'only pull request and repository scans');

  // Picking: files are listed with what is known about them, at most ten can be chosen, and the cost is stated.
  const files = Array.from({length: 12}, (_, i) => ({path: `src/F${i}.java`, findings: i === 0 ? 3 : 0, changed: i < 2}));
  const picker = await load('pull_request', {aiReview: true, ruleDraft: true}, (call) => {
    if (call.url.startsWith('/assistant/ai-review/files/')) return ok({state: 'OK', files, max_files: 10, max_lines: 800});
    if (call.url.startsWith('/assistant/ai-review/scan/')) return ok({state: 'NONE'});
    if (call.url === '/assistant/ai-review' && call.method === 'POST') return ok(run('QUEUED', [], {files_done: 0}));
    return ok(run('RUNNING', [], {files_done: 1}));
  });
  assert.equal(picker.q('[data-ai-review-chip]').hidden, true, 'no review yet');
  const button = picker.q('[data-ai-helper="aiReview"]');
  assert.equal(button.hidden, false);
  button.click();
  await settle();
  assert.equal(picker.q('[data-ai-review-pick]').open, true);
  assert.equal(picker.calls.find((c) => c.url.startsWith('/assistant/ai-review/files/')).url, '/assistant/ai-review/files/pull_request/7');
  assert.equal(picker.all('[data-ai-review-files] input[type=checkbox]').length, 12);
  assert.equal(picker.q('[data-ai-review-start]').disabled, true);
  const boxes = picker.all('[data-ai-review-files] input[type=checkbox]');
  boxes.slice(0, 10).forEach((box) => { box.checked = true; box.dispatchEvent(new picker.w.Event('change', {bubbles: true})); });
  assert.equal(picker.q('[data-ai-review-start-label]').textContent, 'Review 10 files');
  assert.equal(boxes[10].disabled, true, 'the eleventh cannot be chosen');
  assert.equal(boxes[0].disabled, false, 'a chosen file can be unchosen');
  assert.match(picker.q('[data-ai-review-confirm]').textContent, /Up to 80,000 tokens/);
  assert.match(picker.q('[data-ai-review-confirm]').textContent, /Secret lines removed/);
  assert.match(picker.q('[data-ai-review-confirm]').textContent, /Code not kept/);
  boxes[9].checked = false;
  boxes[9].dispatchEvent(new picker.w.Event('change', {bubbles: true}));
  assert.equal(boxes[10].disabled, false);
  assert.equal(picker.q('[data-ai-review-start-label]').textContent, 'Review 9 files');
  // The filter hides rows without removing the choice.
  const filter = picker.q('[data-ai-review-filter]');
  filter.value = 'f11';
  filter.dispatchEvent(new picker.w.Event('input', {bubbles: true}));
  assert.equal(picker.all('[data-ai-review-files] tr').filter((row) => !row.hidden).length, 1);

  // Starting sends only the chosen paths, with CSRF, closes the picker and shows progress that is followed until it ends.
  picker.q('[data-ai-review-start]').click();
  await settle();
  const start = picker.calls.find((c) => c.url === '/assistant/ai-review' && c.method === 'POST');
  assert.equal(start.headers['X-CSRF-TOKEN'], 'fixture');
  assert.deepEqual(start.body.paths, boxes.slice(0, 9).map((box) => box.value));
  assert.equal(start.body.scanType, 'pull_request');
  assert.equal(start.body.scanId, 7);
  assert.equal(picker.q('[data-ai-review-pick]').open, false);
  assert.equal(picker.q('[data-ai-review-results]').open, true);
  assert.match(picker.q('[data-ai-review-summary]').textContent, /Reading 0\/2 files/);
  assert.equal(picker.q('[data-ai-review-chip]').hidden, false);
  assert.equal(picker.timers.length, 1, 'it asks again while the review runs');
  picker.w.close();

  // The result: each point with its coverage, weakness and reason; a person's actions; the text stays text.
  const items = [point(1, {rationale: '<img src=x onerror=alert(1)>', path: 'src/<b>Dao.java'}), point(2, {coverage: 'COVERED', covered_by: 'AvoidConcatenatedSql', scanner: null}),
    point(3, {coverage: 'NOT_CHECKED', confidence: 'low', can_draft: false}), point(4, {state: 'CONFIRMED'})];
  const reading = await load('repository', {aiReview: true, ruleDraft: true}, (call) => {
    if (call.url.startsWith('/assistant/ai-review/scan/') || call.url === '/assistant/ai-review/runs/r1') return ok(run('DONE', items));
    if (call.url === '/assistant/ai-review/items/i1/draft') return ok({state: 'OK', url: `/designer/pmd?draft=${DRAFT}`});
    if (call.url === '/assistant/ai-review/items/i2/draft') return ok({state: 'BLOCKED', message: 'Rules about secrets are never drafted by the assistant.'});
    if (call.url.startsWith('/assistant/ai-review/items/')) return ok({state: 'OK'});
    return ok({});
  });
  const chipEl = reading.q('[data-ai-review-chip]');
  assert.equal(chipEl.hidden, false, 'an earlier review of this scan is offered');
  assert.match(chipEl.textContent, /AI review · 4 points/);
  chipEl.click();
  assert.equal(reading.q('[data-ai-review-results]').open, true);
  const rows = reading.all('[data-ai-review-points] tbody tr');
  assert.equal(rows.length, 4);
  assert.equal(reading.q('[data-ai-review-points] img'), null, 'a reason from the model is text');
  assert.equal(reading.q('[data-ai-review-points] b'), null);
  assert.match(rows[0].textContent, /<b>Dao\.java:10-11/);
  assert.match(rows[0].querySelector('strong').dataset.tip, /src\/<b>Dao\.java, lines 10-11/);
  assert.match(rows[0].querySelector('.wt-muted').textContent, /^<img src=x onerror=alert\(1\)>$/);
  assert.match(rows[0].querySelector('.wt-mini-chip--bad').dataset.tip, /No scanner finding of this scan is on these lines/);
  assert.match(rows[1].querySelector('.wt-mini-chip--ok').dataset.tip, /AvoidConcatenatedSql/);
  assert.match(rows[2].querySelector('.wt-mini-chip--warn').dataset.tip, /kept only some/);
  assert.match(rows[0].querySelector('[data-tip^="SQL Injection"]').dataset.tip, /high confidence\. PMD could catch this/);
  assert.match(rows[3].textContent, /Confirmed/);
  assert.equal(rows[3].querySelector('[data-ai-review-act="confirm"]'), null, 'a confirmed point cannot be confirmed again');
  assert.ok(rows[3].querySelector('[data-ai-review-act="dismiss"]'));
  assert.equal(rows[2].querySelector('[data-ai-review-act="draft"]'), null, 'no draft for a file type rules are not drafted for');
  assert.match(reading.q('[data-ai-review-summary]').textContent, /2 files read/);
  assert.match(reading.q('[data-ai-review-summary]').textContent, /2 gaps/);
  assert.equal(reading.q('[data-ai-review-resume]').hidden, true);

  rows[0].querySelector('[data-ai-review-act="confirm"]').click();
  await settle();
  const confirm = reading.calls.find((c) => c.url === '/assistant/ai-review/items/i1/confirm');
  assert.equal(confirm.method, 'POST');
  assert.equal(confirm.headers['X-CSRF-TOKEN'], 'fixture');
  reading.all('[data-ai-review-points] tbody tr')[0].querySelector('[data-ai-review-act="dismiss"]').click();
  await settle();
  assert.ok(reading.calls.find((c) => c.url === '/assistant/ai-review/items/i1/dismiss'));

  // Drafting a rule: a designer link appears for a draft; a refusal is explained and leaves no link.
  reading.all('[data-ai-review-points] tbody tr')[0].querySelector('[data-ai-review-act="draft"]').click();
  await settle();
  const link = reading.q('[data-ai-review-points] a');
  assert.equal(link.getAttribute('href'), `/designer/pmd?draft=${DRAFT}`);
  assert.match(link.textContent, /Open draft/);
  reading.all('[data-ai-review-points] tbody tr')[1].querySelector('[data-ai-review-act="draft"]').click();
  await settle();
  assert.match(reading.q('[data-ai-review-note]').textContent, /never drafted/);
  assert.equal(reading.all('[data-ai-review-points] a').length, 1);
  reading.w.close();

  // A link that is not exactly a designer draft link is never shown.
  const evil = await load('repository', {aiReview: true, ruleDraft: true}, (call) => {
    if (call.url.startsWith('/assistant/ai-review/scan/') || call.url === '/assistant/ai-review/runs/r1') return ok(run('DONE', [point(1)]));
    if (call.url.endsWith('/draft')) return ok({state: 'OK', url: 'https://evil.example/designer/pmd?draft=' + DRAFT});
    return ok({});
  });
  evil.q('[data-ai-review-act="draft"]').click();
  await settle();
  assert.equal(evil.all('[data-ai-review-points] a').length, 0);
  assert.match(evil.q('[data-ai-review-note]').textContent, /not available/);
  evil.w.close();

  // Without the rule draft helper there is no draft button.
  const noDrafts = await load('repository', {aiReview: true, ruleDraft: false}, () => ok(run('DONE', [point(1)])));
  assert.equal(noDrafts.q('[data-ai-review-act="draft"]'), null);
  noDrafts.w.close();

  // A used-up share stops the review and offers to resume it; resuming asks the server and follows it.
  const stopped = run('PARTIAL_BUDGET', [point(1)], {files_done: 1});
  const budget = await load('repository', {aiReview: true}, (call) => {
    if (call.url === '/assistant/ai-review/runs/r1/resume') return ok(run('QUEUED', [point(1)], {files_done: 1}));
    return ok(stopped);
  });
  budget.q('[data-ai-review-chip]').click();
  assert.match(budget.q('[data-ai-review-summary]').textContent, /Stopped: daily share used up/);
  assert.equal(budget.q('[data-ai-review-resume]').hidden, false);
  budget.q('[data-ai-review-resume]').click();
  await settle();
  assert.equal(budget.calls.find((c) => c.url === '/assistant/ai-review/runs/r1/resume').method, 'POST');
  assert.match(budget.q('[data-ai-review-summary]').textContent, /Reading 1\/2 files/);
  budget.w.close();

  // Many files: the limit comes from the server, a big review is shown in the warning tone, and the select actions tick
  // the files with findings, everything shown (the filter counts), or nothing, never past the limit.
  const many = Array.from({length: 205}, (_, i) => ({path: `src/pkg/F${i}.java`, findings: i < 3 ? 2 : 0, changed: false}));
  const bulk = await load('repository', {aiReview: true}, (call) => {
    if (call.url.startsWith('/assistant/ai-review/files/')) return ok({state: 'OK', files: many, max_files: 200, max_lines: 800});
    if (call.url.startsWith('/assistant/ai-review/scan/')) return ok({state: 'NONE'});
    if (call.url === '/assistant/ai-review' && call.method === 'POST') return ok(run('QUEUED', [], {files_done: 0, files_total: 200, focus: 'input validation'}));
    return ok(run('RUNNING', [], {files_done: 1, focus: 'input validation'}));
  });
  bulk.q('[data-ai-helper="aiReview"]').click();
  await settle();
  const ticked = () => bulk.all('[data-ai-review-files] input[type=checkbox]').filter((box) => box.checked).length;
  const press = (which) => bulk.q(`[data-ai-review-select-action="${which}"]`).click();
  assert.match(bulk.q('[data-ai-review-limits]').textContent, /Choose up to 200/);
  assert.equal(bulk.q('[data-ai-review-select]').hidden, false);
  assert.equal(bulk.q('[data-ai-review-count="findings"]').textContent, '3');
  assert.equal(bulk.q('[data-ai-review-count="shown"]').textContent, '205');
  press('findings');
  assert.equal(ticked(), 3, 'only the files that have findings');
  assert.match(bulk.q('[data-ai-review-confirm]').textContent, /Up to 24,000 tokens/);
  assert.equal(bulk.q('[data-ai-review-confirm] .wt-mini-chip--warn'), null, 'three files is not a big review');
  press('shown');
  assert.equal(ticked(), 200, 'never past the limit');
  assert.match(bulk.q('[data-ai-review-status]').textContent, /Ticked 197 files; 5 left out because a review reads at most 200 files/);
  assert.equal(bulk.q('[data-ai-review-start-label]').textContent, 'Review 200 files');
  assert.match(bulk.q('[data-ai-review-confirm]').textContent, /Up to 1,600,000 tokens/);
  assert.match(bulk.q('[data-ai-review-confirm]').textContent, /About 17 min/);
  assert.equal(bulk.all('[data-ai-review-confirm] .wt-mini-chip--warn').length, 2, 'cost and time are both in the warning tone');
  assert.equal(bulk.all('[data-ai-review-files] input[type=checkbox]').filter((box) => !box.checked).every((box) => box.disabled), true);
  press('clear');
  assert.equal(ticked(), 0);
  assert.equal(bulk.q('[data-ai-review-start]').disabled, true);
  assert.equal(bulk.q('[data-ai-review-status]').textContent, '');
  const bulkFilter = bulk.q('[data-ai-review-filter]');
  bulkFilter.value = 'f19';
  bulkFilter.dispatchEvent(new bulk.w.Event('input', {bubbles: true}));
  assert.equal(bulk.q('[data-ai-review-count="shown"]').textContent, '11', 'F19 and F190 to F199');
  press('shown');
  assert.equal(ticked(), 11, 'only what the filter shows');
  assert.equal(bulk.all('[data-ai-review-confirm] .wt-mini-chip--warn').length, 2, 'more than ten files is a big review');

  // The focus: optional, shown as Set once there is text, sent trimmed with the files, and left out when empty.
  assert.match(bulk.q('[data-ai-review-focus-state]').textContent, /Optional/);
  const focusField = bulk.q('[data-ai-review-focus]');
  focusField.value = '  input validation  ';
  focusField.dispatchEvent(new bulk.w.Event('input', {bubbles: true}));
  assert.match(bulk.q('[data-ai-review-focus-state]').textContent, /Set/);
  assert.ok(bulk.q('[data-ai-review-focus-state]').classList.contains('wt-mini-chip--ok'));
  bulk.q('[data-ai-review-start]').click();
  await settle();
  const bulkStart = bulk.calls.find((c) => c.url === '/assistant/ai-review' && c.method === 'POST');
  assert.equal(bulkStart.body.focus, 'input validation');
  assert.equal(bulkStart.body.paths.length, 11);
  assert.match(bulk.q('[data-ai-review-summary]').textContent, /Focus: input validation/);
  assert.match(bulk.q('[data-ai-review-summary] [data-tip^="Focus given"]').dataset.tip, /input validation/);
  bulk.w.close();
  const plain = await load('pull_request', {aiReview: true}, (call) => {
    if (call.url.startsWith('/assistant/ai-review/files/')) return ok({state: 'OK', files: [{path: 'src/A.java', findings: 0, changed: true}], max_files: 200});
    if (call.url === '/assistant/ai-review' && call.method === 'POST') return ok(run('QUEUED', [], {files_done: 0}));
    return ok({state: 'NONE'});
  });
  plain.q('[data-ai-helper="aiReview"]').click();
  await settle();
  const only = plain.q('[data-ai-review-files] input[type=checkbox]');
  only.checked = true;
  only.dispatchEvent(new plain.w.Event('change', {bubbles: true}));
  plain.q('[data-ai-review-start]').click();
  await settle();
  const plainStart = plain.calls.find((c) => c.url === '/assistant/ai-review' && c.method === 'POST');
  assert.equal('focus' in plainStart.body, false, 'no focus is not sent as an empty one');
  assert.doesNotMatch(plain.q('[data-ai-review-summary]').textContent, /Focus/);
  plain.w.close();

  // A focus the server refuses opens its box and says why, where the person can see it.
  const refusedFocus = await load('pull_request', {aiReview: true}, (call) => {
    if (call.url.startsWith('/assistant/ai-review/files/')) return ok({state: 'OK', files: [{path: 'src/A.java', findings: 0, changed: true}], max_files: 200});
    if (call.url === '/assistant/ai-review' && call.method === 'POST') return fail(400, {error: 'The focus looks like it holds a secret or a token. Say what to look for in plain words.'});
    return ok({state: 'NONE'});
  });
  refusedFocus.q('[data-ai-helper="aiReview"]').click();
  await settle();
  let scrolled = 0;
  refusedFocus.q('[data-ai-review-status]').scrollIntoView = () => { scrolled += 1; };
  const one = refusedFocus.q('[data-ai-review-files] input[type=checkbox]');
  one.checked = true;
  one.dispatchEvent(new refusedFocus.w.Event('change', {bubbles: true}));
  refusedFocus.q('[data-ai-review-focus]').value = 'use key AKIAIOSFODNN7EXAMPLE';
  refusedFocus.q('[data-ai-review-start]').click();
  await settle();
  assert.match(refusedFocus.q('[data-ai-review-status]').textContent, /holds a secret or a token/);
  assert.equal(refusedFocus.q('[data-ai-review-focus-box]').open, true);
  assert.equal(scrolled, 1, 'the refusal is brought into view');
  assert.equal(refusedFocus.q('[data-ai-review-pick]').open, true);
  refusedFocus.w.close();

  // Refusals are explained in the picker and nothing starts.
  const refused = await load('pull_request', {aiReview: true}, (call) => {
    if (call.url.startsWith('/assistant/ai-review/files/')) return ok({state: 'OK', files: [{path: 'src/A.java', findings: 0, changed: true}], max_files: 10});
    if (call.url === '/assistant/ai-review' && call.method === 'POST') return fail(429, {message: 'The daily AI budget for ai code review is used up; try again tomorrow.'});
    return ok({state: 'NONE'});
  });
  refused.q('[data-ai-helper="aiReview"]').click();
  await settle();
  const box = refused.q('[data-ai-review-files] input[type=checkbox]');
  box.checked = true;
  box.dispatchEvent(new refused.w.Event('change', {bubbles: true}));
  refused.q('[data-ai-review-start]').click();
  await settle();
  assert.match(refused.q('[data-ai-review-status]').textContent, /used up/);
  assert.equal(refused.q('[data-ai-review-pick]').open, true);
  assert.equal(refused.q('[data-ai-review-start]').disabled, false, 'it can be tried again');
  refused.w.close();

  // No files to choose from is a picture, not an empty table.
  const nothing = await load('pull_request', {aiReview: true}, (call) => (call.url.startsWith('/assistant/ai-review/files/') ? ok({state: 'OK', files: [], max_files: 10}) : ok({state: 'NONE'})));
  nothing.q('[data-ai-helper="aiReview"]').click();
  await settle();
  assert.match(nothing.q('[data-ai-review-files]').textContent, /changed no source files/);
  assert.equal(nothing.q('[data-ai-review-start]').disabled, true);
  nothing.w.close();
  console.log('ai-review.test.js passed');
}

main().catch((error) => { console.error(error); process.exit(1); });

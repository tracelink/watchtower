const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
const container = fs.readFileSync(path.join(resources, 'templates/fragments/container.html'), 'utf8');
const drawer = container.match(/<wt-assistant-drawer[\s\S]*?<\/wt-assistant-drawer>/)[0];
const helperScript = fs.readFileSync(path.join(resources, 'static/scripts/ai-helpers.js'), 'utf8');
const tick = (ms = 10) => new Promise(resolve => setTimeout(resolve, ms));

/** A page with the drawer and some helper markup; `routes` answers the fetches. */
async function page(body, flags, routes) {
  const dom = new JSDOM(`<body>${drawer}<main id="content">${body}</main></body>`, {url: 'https://watchtower.example/page', runScripts: 'dangerously', pretendToBeVisual: true});
  const w = dom.window; const calls = [];
  w.fetch = async (url, options = {}) => {
    calls.push({url, method: options.method || 'GET', body: options.body, headers: options.headers});
    if (url === '/assistant/helpers') return {ok: true, status: 200, json: async () => flags};
    const answer = routes[(options.method || 'GET') + ' ' + url] || routes[url];
    if (!answer) return {ok: false, status: 404, json: async () => ({error: 'no route ' + url})};
    const reply = typeof answer === 'function' ? answer(options) : answer;
    return {ok: reply.status ? reply.status < 400 : true, status: reply.status || 200, json: async () => reply.body === undefined ? reply : reply.body};
  };
  w.eval(helperScript);
  w.document.querySelector('wt-assistant-drawer').dataset.csrfHeader = 'X-CSRF-TOKEN';
  w.document.querySelector('wt-assistant-drawer').dataset.csrfToken = 'fixture';
  await tick(); await tick();
  return {w, calls, document: w.document, close: () => dom.window.close()};
}

async function main() {
  // Helpers the server says are not ready are removed, and a page with none asks nothing.
  let p = await page('<button data-ai-helper="draft" hidden>d</button><button data-ai-helper="diagnose" data-job-id="1" hidden>x</button>', {draft: true, diagnose: false}, {});
  assert.equal(p.document.querySelector('[data-ai-helper="draft"]').hidden, false);
  assert.equal(p.document.querySelector('[data-ai-helper="diagnose"]'), null, 'a helper that will not work is not shown');
  p.close();
  p = await page('<p>nothing</p>', {draft: true}, {});
  assert.equal(p.calls.length, 0, 'no helper on the page, no request');
  p.close();

  // Share my draft: the button toggles, tells the drawer, and the designer text is collected as labelled lines.
  p = await page('<button data-ai-helper="draft" hidden aria-pressed="false">d</button><div data-ai-draft-scope><textarea name="xpath">//Foo[@Public]</textarea><input name="name" value="AvoidPublicFields"><input type="password" value="hunter2"><input name="empty" value=""><md-outlined-text-field label="Message"></md-outlined-text-field></div>', {draft: true}, {});
  p.document.querySelector('md-outlined-text-field').value = 'No public fields';
  const events = []; p.document.addEventListener('wt:assistant-draft', e => events.push(e.detail.on));
  const pen = p.document.querySelector('[data-ai-helper="draft"]');
  pen.click(); assert.equal(pen.getAttribute('aria-pressed'), 'true'); pen.click(); assert.equal(pen.getAttribute('aria-pressed'), 'false');
  assert.deepEqual(events, [true, false]);
  assert.equal(p.w.WatchtowerAiHelpers.collectDraft(), 'xpath: //Foo[@Public]\nname: AvoidPublicFields\nMessage: No public fields', 'passwords and empty fields are left out');
  pen.click(); p.document.dispatchEvent(new p.w.CustomEvent('wt:assistant-draft-cleared'));
  assert.equal(pen.getAttribute('aria-pressed'), 'false', 'the drawer clearing the draft un-presses the button');
  p.close();

  // Bypass summary: counts as chips; a request that covers a secret turns the chip into "No AI summary".
  const summary = {state: 'OK', reason_code: 'TEST_CODE', total: 10, by_severity: {HIGH: 2, MEDIUM: 8}, files: 2, attention: 'HIGH', risk_note: 'Two High findings are covered; check the files.'};
  p = await page('<div class="wt-ai-summary"><button data-ai-helper="bypass" data-request-id="7" hidden><span class="material-icons">auto_awesome</span><span data-ai-bypass-label>AI summary</span></button><div data-ai-bypass-panel hidden></div></div>', {bypass: true}, {'POST /assistant/bypass-summary/7': summary});
  const chipBtn = p.document.querySelector('[data-ai-helper="bypass"]'), panel = p.document.querySelector('[data-ai-bypass-panel]');
  chipBtn.click(); await tick();
  assert.equal(panel.hidden, false);
  assert.match(panel.textContent, /Asks to bypass 10 findings as test code/);
  assert.match(panel.textContent, /2 files · 2 high, 8 medium/);
  assert.equal(panel.querySelector('[data-tip*="check the files"]') !== null, true, 'the risk note is on hover');
  assert.equal(p.calls.at(-1).headers['X-CSRF-TOKEN'], 'fixture');
  chipBtn.click(); assert.equal(panel.hidden, true, 'a second click folds it away without asking again');
  assert.equal(p.calls.filter(c => c.url.includes('bypass-summary')).length, 1);
  p.close();
  p = await page('<div><button data-ai-helper="bypass" data-request-id="8" hidden><span class="material-icons">auto_awesome</span><span data-ai-bypass-label>AI summary</span></button><div data-ai-bypass-panel hidden></div></div>', {bypass: true}, {'POST /assistant/bypass-summary/8': {state: 'BLOCKED', message: 'This request covers a secret finding. Secret findings are never sent to the AI, so there is no summary.'}});
  const secretBtn = p.document.querySelector('[data-ai-helper="bypass"]');
  secretBtn.click(); await tick();
  assert.equal(secretBtn.querySelector('[data-ai-bypass-label]').textContent, 'No AI summary');
  assert.equal(secretBtn.querySelector('.material-icons').textContent, 'lock');
  assert.equal(secretBtn.classList.contains('wt-mini-chip--bad'), true);
  assert.match(secretBtn.getAttribute('data-tip'), /never sent to the AI/);
  assert.equal(p.document.querySelector('[data-ai-bypass-panel]').hidden, true, 'nothing about a secret request is shown');
  p.close();

  // Diagnose: a small card with cause, next step and a fix link; one click closes it; errors are said plainly.
  p = await page('<table><tr><td><button data-ai-helper="diagnose" data-job-id="5" hidden>x</button></td></tr></table>', {diagnose: true}, {'POST /assistant/diagnose-job/5': {state: 'OK', likely_cause: 'The ECR sign-in was refused.', next_step: 'Replace the credentials.', fix_page: '/apisettings'}});
  const diag = p.document.querySelector('[data-ai-helper="diagnose"]');
  diag.click(); await tick();
  let card = p.document.querySelector('[data-ai-diagnosis]');
  assert.match(card.textContent, /The ECR sign-in was refused\./);
  assert.match(card.textContent, /Replace the credentials\./);
  assert.match(card.textContent, /Suggestion only/);
  assert.match(card.textContent, /No code or secrets were sent/);
  assert.equal(card.querySelector('a').getAttribute('href'), '/apisettings');
  diag.click(); await tick(); assert.equal(p.document.querySelector('[data-ai-diagnosis]'), null, 'a second click closes the card');
  p.document.body.click(); p.close();
  p = await page('<table><tr><td><button data-ai-helper="diagnose" data-job-id="6" hidden>x</button></td></tr></table>', {diagnose: true}, {'POST /assistant/diagnose-job/6': {status: 429, body: {message: 'The daily AI budget for failure diagnosis is used up; try again tomorrow.'}}});
  p.document.querySelector('[data-ai-helper="diagnose"]').click(); await tick();
  assert.match(p.document.querySelector('[data-ai-diagnosis]').textContent, /budget for failure diagnosis is used up/);
  p.close();
  // A link that is not a plain site path is never made.
  p = await page('<table><tr><td><button data-ai-helper="diagnose" data-job-id="9" hidden>x</button></td></tr></table>', {diagnose: true}, {'POST /assistant/diagnose-job/9': {state: 'OK', likely_cause: 'a.', next_step: 'b.', fix_page: 'javascript:alert(1)'}});
  p.document.querySelector('[data-ai-helper="diagnose"]').click(); await tick();
  assert.equal(p.document.querySelector('[data-ai-diagnosis] a'), null);
  p.close();

  // Triage: a button, a chip, one dot per finding that says it is advice; secrets show a lock; budget stop offers Resume.
  const workspace = '<div data-scan-type="pull_request" data-scan-id="58"></div><section data-finding-workspace><md-outlined-button data-ai-helper="triage" hidden><span data-ai-triage-label>Triage scan</span></md-outlined-button><span data-ai-triage-chip hidden><span data-ai-triage-icon></span><span data-ai-triage-text></span></span><span data-ai-seen-chip hidden></span>'
    + '<button data-finding-item data-feedback-key="1">a</button><button data-finding-item data-feedback-key="2">b</button><button data-finding-item data-feedback-key="3">c</button></section>';
  let state = {state: 'NONE'};
  p = await page(workspace, {triage: true}, {'GET /assistant/batch-triage/pull_request/58': () => state, 'POST /assistant/batch-triage': () => state});
  const triage = p.document.querySelector('[data-ai-helper="triage"]'), chipT = p.document.querySelector('[data-ai-triage-chip]');
  assert.equal(triage.hidden, false); assert.equal(chipT.hidden, true);
  p.w.WatchtowerAiHelpers.settings.pollMs = 20;
  state = {state: 'RUNNING', total: 3, done: 1, blocked: 1, items: [{key: '1', status: 'BLOCKED_SECRET'}, {key: '2', status: 'PENDING'}, {key: '3', status: 'PENDING'}]};
  triage.click(); await tick(30);
  assert.equal(triage.hidden, true, 'the button steps aside while it runs');
  assert.match(chipT.textContent, /Triage 0\/2/, 'withheld findings are not counted as triaged');
  assert.equal(p.document.querySelector('[data-feedback-key="1"] [data-ai-dot]').getAttribute('data-tip'), 'Secret finding. It was not sent to the AI.');
  assert.equal(p.document.querySelector('[data-feedback-key="2"] [data-ai-dot]').getAttribute('data-tip'), 'Waiting for its turn.');
  assert.equal(p.document.querySelector('[data-ai-seen-chip]').hidden, true, 'no verdict seen yet');
  state = {state: 'DONE', total: 3, done: 3, blocked: 1, items: [{key: '1', status: 'BLOCKED_SECRET'}, {key: '2', status: 'DONE', verdict: 'LIKELY_FALSE_POSITIVE'}, {key: '3', status: 'DONE', verdict: 'LIKELY_TRUE_POSITIVE'}]};
  await tick(60);
  assert.match(chipT.textContent, /Triage 2\/2/);
  assert.equal(triage.hidden, true, 'a finished triage has nothing left to start');
  assert.match(chipT.getAttribute('data-tip'), /Advice for 2 findings; 1 was not sent \(a secret finding, or a finding whose rule was not recorded\)\./);
  assert.match(p.document.querySelector('[data-feedback-key="2"] [data-ai-dot]').getAttribute('data-tip'), /likely false positive\. Not a verdict; you decide\./);
  assert.match(p.document.querySelector('[data-feedback-key="3"] [data-ai-dot]').getAttribute('data-tip'), /likely true positive/);
  assert.equal(p.document.querySelector('[data-ai-seen-chip]').hidden, false, 'seeing verdicts is said out loud');
  p.close();
  // Nothing could be sent: a finding whose rule was never recorded is withheld, but not called a secret, and a finished run does not look like a success.
  state = {state: 'DONE', total: 3, done: 3, blocked: 3, items: [{key: '1', status: 'BLOCKED_UNKNOWN'}, {key: '2', status: 'BLOCKED_UNKNOWN'}, {key: '3', status: 'BLOCKED_SECRET'}]};
  p = await page(workspace, {triage: true}, {'GET /assistant/batch-triage/pull_request/58': () => state, 'POST /assistant/batch-triage': () => state});
  await tick();
  assert.match(p.document.querySelector('[data-ai-triage-text]').textContent, /None to triage/);
  assert.equal(p.document.querySelector('[data-ai-triage-icon]').textContent, 'info', 'not a green check');
  assert.match(p.document.querySelector('[data-ai-triage-chip]').getAttribute('data-tip'), /None of the 3 findings could be sent/);
  assert.equal(p.document.querySelector('[data-feedback-key="1"] [data-ai-dot]').getAttribute('data-tip'), 'Not sent to the AI: the rule behind this finding was not recorded, so it cannot be checked for secrets.');
  assert.equal(p.document.querySelector('[data-feedback-key="3"] [data-ai-dot]').getAttribute('data-tip'), 'Secret finding. It was not sent to the AI.');
  p.close();
  state = {state: 'PARTIAL_BUDGET', total: 3, done: 2, blocked: 0, items: [{key: '1', status: 'DONE', verdict: 'NEEDS_REVIEW'}, {key: '2', status: 'DONE', verdict: 'NEEDS_REVIEW'}, {key: '3', status: 'PENDING'}]};
  p = await page(workspace, {triage: true}, {'GET /assistant/batch-triage/pull_request/58': () => state, 'POST /assistant/batch-triage': () => state});
  await tick();
  assert.equal(p.document.querySelector('[data-ai-triage-label]').textContent, 'Resume');
  assert.match(p.document.querySelector('[data-ai-triage-text]').textContent, /Triage 2\/3 · limit reached/);
  p.close();
  // When the server names the limit, the tip repeats it so a person's token cap is not blamed on the feature's share.
  state = {state: 'PARTIAL_BUDGET', total: 3, done: 2, blocked: 0, limit: 'The daily AI limit for batch triage is reached: your daily token limit (200,000 tokens).', items: [{key: '1', status: 'DONE', verdict: 'NEEDS_REVIEW'}, {key: '2', status: 'DONE', verdict: 'NEEDS_REVIEW'}, {key: '3', status: 'PENDING'}]};
  p = await page(workspace, {triage: true}, {'GET /assistant/batch-triage/pull_request/58': () => state, 'POST /assistant/batch-triage': () => state});
  await tick();
  assert.match(p.document.querySelector('[data-ai-triage-chip]').getAttribute('data-tip'), /your daily token limit \(200,000 tokens\)\. Resume to finish the rest/);
  p.close();
  // A refusal (feature off, budget) is shown as a quiet chip, not an error page.
  p = await page(workspace, {triage: true}, {'GET /assistant/batch-triage/pull_request/58': {state: 'NONE'}, 'POST /assistant/batch-triage': {status: 429, body: {message: 'The daily AI budget for batch triage is used up; try again tomorrow.'}}});
  p.document.querySelector('[data-ai-helper="triage"]').click(); await tick();
  assert.match(p.document.querySelector('[data-ai-triage-chip]').getAttribute('data-tip'), /budget for batch triage is used up/);
  p.close();
  // Upload and image reports are not triaged.
  p = await page(workspace.replace('pull_request', 'upload'), {triage: true}, {});
  assert.equal(p.document.querySelector('[data-ai-helper="triage"]'), null);
  p.close();
  // Suggest a ruleset: one card with the pick, the evidence and a link to the review page; it assigns nothing.
  const anchor = '<span class="wt-ai-anchor" data-ai-helper="onboarding" hidden><button type="button" data-repo-id="12" aria-expanded="false"><span class="material-icons">rule</span></button></span>';
  const suggestion = {state: 'OK', language: 'Java', current: null, ruleset: {id: 3, name: 'Default Dev Ruleset'}, peers: {using: 13, total: 17}, reason: 'Most Java repositories already use it.',
    changeSetId: 'a1b2c3d4-0000-4000-8000-000000000001', reviewUrl: '/assistant/change-sets/a1b2c3d4-0000-4000-8000-000000000001/review'};
  p = await page(anchor, {onboarding: true}, {'POST /assistant/onboarding/12': suggestion});
  const suggestBtn = p.document.querySelector('[data-ai-helper="onboarding"] button');
  assert.equal(p.document.querySelector('[data-ai-helper="onboarding"]').hidden, false);
  suggestBtn.click(); await tick();
  const pickCard = p.document.querySelector('[data-ai-suggestion]');
  assert.match(pickCard.textContent, /Suggested ruleset/); assert.match(pickCard.textContent, /Default Dev Ruleset/); assert.match(pickCard.textContent, /No ruleset today/);
  assert.match(pickCard.textContent, /13 of 17 Java repos/); assert.match(pickCard.textContent, /Most Java repositories already use it\./); assert.match(pickCard.textContent, /Needs your approval/); assert.match(pickCard.textContent, /No code was sent/);
  assert.equal(pickCard.querySelector('a').getAttribute('href'), suggestion.reviewUrl);
  assert.equal(p.calls.filter(c => c.method === 'POST').length, 1, 'only the suggestion is asked for; nothing is applied');
  assert.equal(p.calls.at(-1).headers['X-CSRF-TOKEN'], 'fixture');
  suggestBtn.click(); assert.equal(p.document.querySelector('[data-ai-suggestion]'), null, 'a second click closes the card');
  p.close();
  // A link that is not a change-set review page is never used, and "already fits" and "actions off" have no button.
  p = await page(anchor, {onboarding: true}, {'POST /assistant/onboarding/12': {...suggestion, reviewUrl: 'https://evil.example/x'}});
  p.document.querySelector('[data-ai-helper="onboarding"] button').click(); await tick();
  assert.equal(p.document.querySelector('[data-ai-suggestion] a'), null);
  p.close();
  p = await page(anchor, {onboarding: true}, {'POST /assistant/onboarding/12': {state: 'FITS', language: 'Java', current: {id: 3, name: 'Default Dev Ruleset'}, ruleset: {id: 3, name: 'Default Dev Ruleset'}, peers: {using: 13, total: 17}, reason: 'It is the most used one.'}});
  p.document.querySelector('[data-ai-helper="onboarding"] button').click(); await tick();
  assert.match(p.document.querySelector('[data-ai-suggestion]').textContent, /Already uses Default Dev Ruleset/);
  assert.equal(p.document.querySelector('[data-ai-suggestion] a'), null);
  p.document.body.click(); assert.equal(p.document.querySelector('[data-ai-suggestion]'), null, 'a click elsewhere closes it');
  p.close();
  p = await page(anchor, {onboarding: true}, {'POST /assistant/onboarding/12': {state: 'ACTIONS_OFF', message: 'Preparing a change needs Ruleset actions.'}});
  p.document.querySelector('[data-ai-helper="onboarding"] button').click(); await tick();
  assert.match(p.document.querySelector('[data-ai-suggestion]').textContent, /Ruleset actions are off/);
  p.close();
  p = await page(anchor, {onboarding: false}, {});
  assert.equal(p.document.querySelector('[data-ai-helper="onboarding"]'), null, 'not shown when it will not work');
  p.close();

  // Draft fixture: shown in the dialog, marked as not saved, copyable; a secret on the line gives a lock and no code.
  const dialogHtml = '<div data-variant-dialog data-case-id="11111111-1111-1111-1111-111111111111"><button data-ai-helper="fixture" hidden>Draft fixture</button><div data-ai-fixture-result></div></div>';
  const exampleCode = 'String v = req.getParameter("q");\nresp.getWriter().write(v);';
  p = await page(dialogHtml, {fixture: true}, {'POST /assistant/draft-fixture/11111111-1111-1111-1111-111111111111': {state: 'OK', expected: 'MATCH', example: exampleCode, note: 'Writes a request parameter into the response.'}});
  let copied = null; Object.defineProperty(p.w.navigator, 'clipboard', {value: {writeText: text => { copied = text; return Promise.resolve(); }}, configurable: true});
  p.document.querySelector('[data-ai-helper="fixture"]').click(); await tick();
  const result = p.document.querySelector('[data-ai-fixture-result]');
  assert.match(result.textContent, /Draft only · not saved/); assert.match(result.textContent, /Should match/); assert.match(result.textContent, /Secrets are never sent/);
  assert.equal(result.querySelector('pre').textContent, exampleCode); assert.match(result.textContent, /Check it against your rule before you keep it\./);
  result.querySelector('button[aria-label="Copy the example"]').click(); assert.equal(copied, exampleCode);
  assert.equal(p.calls.filter(c => c.method === 'POST').length, 1);
  p.close();
  p = await page(dialogHtml, {fixture: true}, {'POST /assistant/draft-fixture/11111111-1111-1111-1111-111111111111': {state: 'BLOCKED', message: 'A secret was recorded on or near this line, so it is never sent to the AI and no example was drafted.'}});
  p.document.querySelector('[data-ai-helper="fixture"]').click(); await tick();
  assert.match(p.document.querySelector('[data-ai-fixture-result]').textContent, /A secret was recorded/);
  assert.equal(p.document.querySelector('[data-ai-fixture-result] pre'), null, 'no code for a blocked case');
  assert.equal(p.document.querySelector('[data-ai-fixture-result] .material-icons').textContent, 'lock');
  p.close();
  p = await page('<div data-variant-dialog><button data-ai-helper="fixture" hidden>Draft fixture</button><div data-ai-fixture-result></div></div>', {fixture: true}, {});
  p.document.querySelector('[data-ai-helper="fixture"]').click(); await tick();
  assert.equal(p.calls.filter(c => c.method === 'POST').length, 0, 'nothing is asked until a case is open');
  p.close();
  // A suggestion is shown again until its draft expires instead of preparing another one.
  p = await page(anchor, {onboarding: true}, {'POST /assistant/onboarding/12': {...suggestion, expiresAt: Date.now() + 1800000}});
  const again = p.document.querySelector('[data-ai-helper="onboarding"] button');
  again.click(); await tick(); again.click(); again.click(); await tick();
  assert.match(p.document.querySelector('[data-ai-suggestion]').textContent, /Default Dev Ruleset/);
  assert.equal(p.calls.filter(c => c.method === 'POST').length, 1, 'opening it again does not ask, or prepare, again');
  assert.match(p.document.querySelector('[data-ai-suggestion] [data-tip*="30 minutes"]').textContent, /Needs your approval/);
  p.close();
  p = await page(anchor, {onboarding: true}, {'POST /assistant/onboarding/12': {...suggestion, expiresAt: Date.now() + 1000}});
  const expired = p.document.querySelector('[data-ai-helper="onboarding"] button');
  expired.click(); await tick(); expired.click(); expired.click(); await tick();
  assert.equal(p.calls.filter(c => c.method === 'POST').length, 2, 'a draft about to expire is not offered again');
  p.close();

  // An answer for a case that is no longer open never shows under another case; a failed copy says so.
  let release; const slow = new Promise(resolve => { release = resolve; });
  p = await page(dialogHtml, {fixture: true}, {'POST /assistant/draft-fixture/11111111-1111-1111-1111-111111111111': () => slow});
  const staleDialog = p.document.querySelector('[data-variant-dialog]');
  p.document.querySelector('[data-ai-helper="fixture"]').click(); await tick();
  staleDialog.dataset.caseId = '22222222-2222-2222-2222-222222222222';
  staleDialog.querySelector('[data-ai-fixture-result]').replaceChildren();
  release({state: 'OK', expected: 'MATCH', example: 'int a = 1;', note: 'x'}); await tick();
  assert.equal(staleDialog.querySelector('[data-ai-fixture-result]').textContent, '', 'the answer for the first case is dropped');
  p.close();
  p = await page(dialogHtml, {fixture: true}, {'POST /assistant/draft-fixture/11111111-1111-1111-1111-111111111111': {state: 'OK', expected: 'MATCH', example: 'int a = 1;', note: 'x'}});
  Object.defineProperty(p.w.navigator, 'clipboard', {value: {writeText: () => Promise.reject(new Error('denied'))}, configurable: true});
  p.document.querySelector('[data-ai-helper="fixture"]').click(); await tick();
  const copyBtn = p.document.querySelector('button[aria-label="Copy the example"]');
  copyBtn.click(); await tick();
  assert.equal(copyBtn.getAttribute('data-tip'), 'Copy is not available here', 'a refused copy is not reported as copied');
  p.close();
  console.log('AI helpers: draft, bypass summary, diagnosis, triage, ruleset suggestion and fixture draft tests passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});

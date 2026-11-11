const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const script = fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/home-digest.js'), 'utf8');
const tick = (ms = 10) => new Promise(resolve => setTimeout(resolve, ms));
const markup = '<div id="head"><span data-home-digest hidden data-csrf-header="X-CSRF-TOKEN" data-csrf-token="fixture"><button type="button" aria-expanded="false"><span data-digest-label>Weekly digest</span></button></span></div>';

async function page(routes) {
  const dom = new JSDOM(`<body>${markup}</body>`, {url: 'https://watchtower.example/', runScripts: 'dangerously', pretendToBeVisual: true});
  const w = dom.window, calls = [];
  w.fetch = async (url, options = {}) => {
    calls.push({url, method: options.method || 'GET', headers: options.headers});
    const answer = routes[options.method || 'GET'];
    const reply = typeof answer === 'function' ? answer() : answer;
    const failed = reply.body !== undefined && reply.status >= 400;
    return {ok: !failed, status: failed ? reply.status : 200, json: async () => reply.body === undefined ? reply : reply.body};
  };
  w.eval(script); await tick(); await tick();
  return {w, calls, document: w.document, anchor: w.document.querySelector('[data-home-digest]'), close: () => w.close()};
}
const WEEK = 7 * 24 * 3600 * 1000, END = Date.UTC(2026, 9, 21);
const digest = (over = {}) => ({id: 'd1', trigger: 'SCHEDULED', createdAt: Date.UTC(2026, 9, 21, 6, 23), windowStart: END - WEEK, windowEnd: END, status: 'OK',
  counts: {this_week: {scans_finished: 4532, scans_failed_or_incomplete: 1, findings: 4040}, last_week: {}, now: {integrations_failing: 4}},
  points: [{trend: 'steady', text: '4,532 scans finished and 1 failed or stopped early.'}, {trend: 'up', text: 'Findings rose to 4,040, up 6% on the week before.'}, {trend: 'attention', text: '4 integrations are failing their health check.'}], ...over});

async function main() {
  // Nothing to show: the feature is off, or no digest yet and the person cannot write one, or the request fails.
  let p = await page({GET: {enabled: false, canWrite: false, digest: null}});
  assert.equal(p.document.querySelector('[data-home-digest]'), null, 'off: no chip'); p.close();
  p = await page({GET: {enabled: true, canWrite: false, digest: null}});
  assert.equal(p.document.querySelector('[data-home-digest]'), null, 'nothing to read and cannot write: no chip'); p.close();
  p = await page({GET: {status: 503, body: {error: 'down'}}});
  assert.equal(p.document.querySelector('[data-home-digest]'), null, 'a failed read leaves the page as it was'); p.close();

  // A digest: the chip, then the popover with three lines, trend tiles and three chips.
  p = await page({GET: {enabled: true, canWrite: true, digest: digest()}, POST: {state: 'OK', digest: digest({points: [{trend: 'down', text: 'Findings fell to 4,040.'}]})}});
  assert.equal(p.anchor.hidden, false); assert.equal(p.document.querySelector('[data-digest-label]').textContent, 'Weekly digest');
  const button = p.anchor.querySelector('button'); button.click();
  const pop = p.document.querySelector('.wt-ai-popover'); assert.ok(pop); assert.equal(button.getAttribute('aria-expanded'), 'true');
  assert.equal(pop.querySelectorAll('.wt-ai-trend-line').length, 3); assert.ok(pop.querySelector('.wt-ai-trend--up')); assert.ok(pop.querySelector('.wt-ai-trend--attention'));
  assert.match(pop.textContent, /Last 7 days/, 'it covers the seven whole days before today, not the current week'); assert.doesNotMatch(pop.textContent, /This week/); assert.match(pop.textContent, /Oct 14 – 20/); assert.match(pop.textContent, /AI summary of counts/); assert.match(pop.textContent, /No findings or names/); assert.match(pop.textContent, /Findings rose to 4,040/);
  // Refresh writes a new one, with the CSRF header, and shows it.
  pop.querySelector('[data-digest-refresh]').click(); await tick();
  assert.equal(p.calls.find(c => c.method === 'POST').headers['X-CSRF-TOKEN'], 'fixture'); assert.match(p.document.querySelector('.wt-ai-popover').textContent, /Findings fell to 4,040/);
  // Escape and a click elsewhere close it.
  p.document.dispatchEvent(new p.w.KeyboardEvent('keydown', {key: 'Escape'})); assert.equal(p.document.querySelector('.wt-ai-popover'), null);
  button.click(); assert.ok(p.document.querySelector('.wt-ai-popover')); p.document.body.click(); assert.equal(p.document.querySelector('.wt-ai-popover'), null); p.close();

  // Counts only: the numbers stay and a plain note says why there is no summary.
  p = await page({GET: {enabled: true, canWrite: false, digest: digest({status: 'COUNTS_ONLY', points: []})}});
  p.anchor.querySelector('button').click(); const counts = p.document.querySelector('.wt-ai-popover');
  assert.match(counts.textContent, /4,532 scans/); assert.match(counts.textContent, /1 failed/); assert.match(counts.textContent, /4,040 findings/); assert.match(counts.textContent, /4 integrations failing/); assert.match(counts.textContent, /could not write a summary/);
  assert.equal(counts.querySelector('[data-digest-refresh]'), null, 'someone who cannot write has no refresh'); p.close();

  // No digest yet: a Write digest button; a limit or used-up budget is said plainly.
  p = await page({GET: {enabled: true, canWrite: true, digest: null}, POST: {status: 429, body: {error: 'The daily AI budget for home digest is used up; try again tomorrow.'}}});
  assert.equal(p.document.querySelector('[data-digest-label]').textContent, 'Digest');
  p.anchor.querySelector('button').click(); assert.match(p.document.querySelector('.wt-ai-popover').textContent, /No digest yet/);
  p.document.querySelector('[data-digest-write]').click(); await tick();
  assert.match(p.document.querySelector('.wt-ai-popover').textContent, /budget .* used up/); assert.ok(p.document.querySelector('.wt-ai-note--warn')); p.close();
  console.log('Home digest: chip, popover, refresh and empty states passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});

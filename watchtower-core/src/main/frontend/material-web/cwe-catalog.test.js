const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const script = fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/cwe-catalog.js'), 'utf8');
const tick = async (n = 6) => { for (let i = 0; i < n; i++) await new Promise(resolve => setTimeout(resolve, 0)); };

const markup = state => `
<section data-knowledge-page data-csrf-header="X-CSRF-TOKEN" data-csrf-token="fixture">
 <span class="wt-mini-chip" data-cwe-catalog data-state="${state}" data-tip="old tip"><span class="material-icons" data-cwe-catalog-icon>menu_book</span><span data-cwe-catalog-label>CWE 4.19 · 960</span></span>
 <button type="button" data-cwe-catalog-update><span class="material-icons">sync</span></button>
</section>`;

const chip = (state, label, tone = '', updating = false) => ({state, label, tip: label + ' tip', icon: state === 'OK' ? 'menu_book' : 'sync', tone, updating});

function setup(state, respond) {
  const dom = new JSDOM(`<body>${markup(state)}</body>`, {url: 'https://watchtower.example/rules/knowledge', runScripts: 'dangerously'});
  const w = dom.window;
  const requests = [];
  const timers = [];
  w.fetch = async (url, options = {}) => {
    requests.push({url, options});
    const reply = respond(url, options, requests.length);
    return {ok: reply.status === 200, status: reply.status, json: async () => reply.body};
  };
  // Polling is driven by hand so the test never waits for a real delay.
  w.setTimeout = (fn, ms) => { timers.push({fn, ms}); return timers.length; };
  w.eval(script);
  const q = selector => w.document.querySelector(selector);
  return {w, requests, timers, q};
}

async function main() {
  // Pressing the button asks for an update with CSRF, then follows the update until it ends.
  let polls = 0;
  const page = setup('OK', (url, options) => {
    if (options.method === 'POST') return {status: 200, body: {queued: true, chip: chip('UPDATING', 'Updating…', 'info', true)}};
    polls += 1;
    return {status: 200, body: polls < 2 ? chip('UPDATING', 'Updating…', 'info', true) : chip('OK', 'CWE 4.20 · 969')};
  });
  page.q('[data-cwe-catalog-update]').click();
  await tick();
  const post = page.requests[0];
  assert.equal(post.url, '/rules/knowledge/cwe-catalog/refresh?force=false');
  assert.equal(post.options.method, 'POST');
  assert.equal(post.options.headers['X-CSRF-TOKEN'], 'fixture');
  assert.equal(page.q('[data-cwe-catalog-label]').textContent, 'Updating…');
  assert.equal(page.q('[data-cwe-catalog]').dataset.state, 'UPDATING');
  assert.ok(page.q('[data-cwe-catalog]').classList.contains('wt-mini-chip--info'));
  assert.equal(page.q('[data-cwe-catalog-update]').disabled, true, 'a second press while updating does nothing');
  assert.equal(page.timers.length, 1);
  page.timers[0].fn();
  await tick();
  assert.equal(page.requests[1].url, '/rules/knowledge/cwe-catalog');
  assert.equal(page.requests[1].options.method, undefined);
  assert.equal(page.timers.length, 2, 'still updating, so it asks again');
  page.timers[1].fn();
  await tick();
  assert.equal(page.q('[data-cwe-catalog-label]').textContent, 'CWE 4.20 · 969');
  assert.equal(page.q('[data-cwe-catalog]').dataset.tip, 'CWE 4.20 · 969 tip');
  assert.equal(page.q('[data-cwe-catalog-icon]').textContent, 'menu_book');
  assert.equal(page.q('[data-cwe-catalog]').classList.contains('wt-mini-chip--info'), false);
  assert.equal(page.q('[data-cwe-catalog-update]').disabled, false);
  assert.equal(page.timers.length, 2, 'finished, so it stops asking');

  // A page opened while an update is already running follows it without a click.
  const running = setup('UPDATING', () => ({status: 200, body: chip('OK', 'CWE 4.20 · 969')}));
  assert.equal(running.timers.length, 1);
  running.timers[0].fn();
  await tick();
  assert.equal(running.q('[data-cwe-catalog-label]').textContent, 'CWE 4.20 · 969');

  // A refused request is shown on the chip and the button works again.
  const refused = setup('OK', () => ({status: 403, body: {}}));
  refused.q('[data-cwe-catalog-update]').click();
  await tick();
  assert.match(refused.q('[data-cwe-catalog]').dataset.tip, /could not start/i);
  assert.equal(refused.q('[data-cwe-catalog-update]').disabled, false);
  assert.equal(refused.timers.length, 0);

  // Nothing to do on a page without the chip.
  const bare = new JSDOM('<body><section data-knowledge-page></section></body>', {runScripts: 'dangerously'});
  bare.window.eval(script);

  // Label text is written as text, never as markup.
  const hostile = setup('OK', () => ({status: 200, body: {queued: true, chip: chip('FAILED', '<img src=x onerror=alert(1)>', 'warn')}}));
  hostile.q('[data-cwe-catalog-update]').click();
  await tick();
  assert.equal(hostile.q('[data-cwe-catalog] img'), null);
  console.log('cwe-catalog tests passed');
}

main().catch(error => { console.error(error); process.exit(1); });

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../../../../watchtower-module-advisory/src/main/resources/static/scripts/advisory-designer.js'),
  'utf8');
const dom = new JSDOM(`<!doctype html><body>
  <form data-advisory-filters>
    <input type="search" name="search" data-advisory-search>
    <select name="minScore" data-advisory-min-score><option value="0">Any</option><option value="7">7.0</option></select>
    <select name="sort" data-advisory-sort><option value="score">Score</option><option value="name">ID</option></select>
    <button type="submit">Filter</button>
  </form>
  <table><tbody data-advisory-rows><tr><td>Loading</td></tr></tbody></table>
  <span data-advisory-status></span>
  <div class="wt-pagination__actions"><button type="button" data-advisory-previous disabled>Previous</button>
  <button type="button" data-advisory-next disabled>Next</button></div>
  <div id="saveAdvisoryRuleDialog"></div>
  <input type="hidden" id="advisoryName"><strong data-advisory-name-label></strong><span data-advisory-score-label></span>
  <button id="cancelSaveAdvisoryRuleDialog"></button>
</body>`, {runScripts: 'dangerously'});

const requests = [];
const dialog = dom.window.document.querySelector('#saveAdvisoryRuleDialog');
dialog.show = () => { dialog.dataset.open = 'true'; };
dialog.close = () => { delete dialog.dataset.open; };
dom.window.fetch = (url) => {
  requests.push(url);
  const page = Number(new URL(url, 'https://watchtower.example').searchParams.get('page'));
  return Promise.resolve({
    ok: true,
    json: () => Promise.resolve({total: 26, page: page, size: 25, advisories: [{
      advisoryName: page === 0 ? 'CVE-2026-0001' : 'CVE-2026-0026',
      score: 8.1,
      description: '<img src=x>',
      uri: 'https://example.test/advisory'
    }]})
  });
};
dom.window.eval(script);
const tick = () => new Promise(resolve => setTimeout(resolve, 0));

(async () => {
  await tick(); await tick();
  const document = dom.window.document;
  assert.match(requests[0], /^\/rest\/advisory\/search\?/);
  assert.match(requests[0], /sort=score/);
  assert.equal(document.querySelectorAll('[data-advisory-rows] tr').length, 1);
  assert.equal(document.querySelector('[data-advisory-rows] img'), null);
  assert.match(document.querySelector('[data-advisory-rows]').textContent, /<img src=x>/);
  assert.equal(document.querySelector('[data-advisory-rows] a').rel, 'noopener noreferrer');
  assert.equal(document.querySelector('[data-advisory-status]').textContent, '1–25 of 26 advisories');
  assert.equal(document.querySelector('[data-advisory-previous]').disabled, true);
  assert.equal(document.querySelector('[data-advisory-next]').disabled, false);
  assert.equal(document.querySelector('.wt-pagination__actions').hidden, false, '26 advisories need two pages');

  // The advisory ID is the link; the score is a CVSS chip coloured by its band (8.1 = high).
  assert.match(document.querySelector('[data-advisory-rows] th a').textContent, /^CVE-2026-0001/);
  const chip = document.querySelector('[data-advisory-rows] .wt-cvss-chip');
  assert.equal(chip.className, 'wt-sev wt-cvss-chip wt-sev-1');
  assert.equal(chip.dataset.tip, 'CVSS 8.1: high');
  assert.equal(document.querySelector('[data-advisory-rows]').textContent.includes('Open advisory'), false);
  // One allowlist icon per row names the advisory as text in the confirmation dialog.
  const allow = document.querySelector('[data-advisory-rows] button[data-advisory-allow]');
  assert.equal(allow.getAttribute('aria-label'), 'Ignore CVE-2026-0001');
  assert.equal(allow.dataset.tip, 'Ignore advisory');
  allow.click();
  assert.equal(document.querySelector('#advisoryName').value, 'CVE-2026-0001');
  assert.equal(document.querySelector('[data-advisory-name-label]').textContent, 'CVE-2026-0001');
  assert.equal(document.querySelector('[data-advisory-score-label]').textContent, 'Score 8.1');
  assert.equal(dialog.dataset.open, 'true');

  // Next page keeps the filters; a new search starts again from the first page.
  document.querySelector('[data-advisory-next]').click();
  await tick(); await tick();
  assert.match(requests.at(-1), /page=1/);
  assert.equal(document.querySelector('[data-advisory-status]').textContent, '26–26 of 26 advisories');
  document.querySelector('[data-advisory-search]').value = 'openssl';
  document.querySelector('[data-advisory-min-score]').value = '7';
  document.querySelector('[data-advisory-filters]').dispatchEvent(new dom.window.Event('submit', {bubbles: true, cancelable: true}));
  await tick(); await tick();
  assert.match(requests.at(-1), /search=openssl/);
  assert.match(requests.at(-1), /minScore=7/);
  assert.match(requests.at(-1), /page=0/);
  // The sort chip applies at once.
  const before = requests.length;
  document.querySelector('[data-advisory-sort]').value = 'name';
  document.querySelector('[data-advisory-sort]').dispatchEvent(new dom.window.Event('change', {bubbles: true}));
  await tick(); await tick();
  assert.equal(requests.length, before + 1);
  assert.match(requests.at(-1), /sort=name/);
  console.log('Advisory designer: server search, score filter, sort, paging, safe rendering and allowlist dialog passed');
})().catch(error => { console.error(error); process.exitCode = 1; });

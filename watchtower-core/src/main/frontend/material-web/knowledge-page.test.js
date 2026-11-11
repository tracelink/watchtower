const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
const tick = async (n = 8) => { for (let i = 0; i < n; i++) await new Promise(resolve => setTimeout(resolve, 0)); };

// Server-rendered markup as the page would produce it for a steward (Thymeleaf attributes resolved).
const markup = `
<section data-knowledge-page data-csrf-header="X-CSRF-TOKEN" data-csrf-token="fixture">
 <p data-knowledge-status role="status"></p>
 <table><tbody><tr data-knowledge-entry><td>
  <md-outlined-button type="button" data-knowledge-decision="approve" data-id="k1" data-version="3">Approve</md-outlined-button>
  <md-text-button type="button" data-knowledge-decision="retire" data-id="k2" data-version="5">Retire</md-text-button>
 </td></tr></tbody></table>
 <details data-knowledge-propose open><form data-knowledge-form>
  <select data-knowledge-kind><option value="SANITIZER">Sanitizer</option></select>
  <textarea data-knowledge-statement></textarea><input data-knowledge-language><input data-knowledge-library>
  <input data-knowledge-versions><input type="checkbox" data-knowledge-all-repositories><input data-knowledge-cwes>
  <fieldset data-knowledge-picker="repositories"><input type="search" data-picker-search><ul data-picker-results></ul><ul data-picker-selected></ul></fieldset>
  <fieldset data-knowledge-picker="rules"><input type="search" data-picker-search><ul data-picker-results></ul>
   <ul data-picker-selected><li data-picker-value="7"><span>Fixture rule (regex)</span><button type="button" data-picker-remove>Remove</button></li></ul></fieldset>
  <fieldset data-knowledge-picker="evidence"><select data-picker-type><option value="review">Review</option><option value="missed_case">Missed</option></select>
   <input type="search" data-picker-search><ul data-picker-results></ul>
   <ul data-picker-selected><li data-picker-value="r-55" data-picker-type="review"><span>Accepted review: Encoder</span><button type="button" data-picker-remove>Remove</button></li></ul></fieldset>
  <input type="date" data-knowledge-review-by>
  <button type="submit">Propose</button>
 </form></details>
</section>`;

async function setup(respond) {
  const dom = new JSDOM(`<body>${markup}</body>`, {url: 'https://watchtower.example/rules/knowledge', runScripts: 'dangerously'});
  const w = dom.window;
  const requests = [];
  const navigations = [];
  w.fetch = async (url, options = {}) => {
    requests.push({url, options});
    const reply = respond(url, options);
    return {ok: reply.status === 200, status: reply.status, json: async () => reply.body};
  };
  w.prompt = () => 'Library upgraded';
  w.WatchtowerKnowledgeNavigate = url => navigations.push(url);
  w.eval(fs.readFileSync(path.join(resources, 'static/scripts/knowledge-page.js'), 'utf8'));
  const q = selector => w.document.querySelector(selector);
  return {w, requests, navigations, q};
}

async function main() {
  const page = await setup((url, options) => {
    if (url.startsWith('/rules/knowledge/options/repositories')) {
      return {status: 200, body: {content: [{id: '42', label: '<img src=x onerror=alert(1)> payments-api', preview: null}]}};
    }
    if (options.method && url === '/rule/knowledge') {
      const body = JSON.parse(options.body);
      return body.statement.length < 10 ? {status: 400, body: {error: 'Statement must be 10 to 300 characters'}} : {status: 200, body: {id: 'k9'}};
    }
    return {status: 200, body: {status: 'APPROVED'}};
  });

  // Decisions send the entry version with CSRF; retire asks for a reason.
  page.q('[data-knowledge-decision="approve"]').click();
  await tick();
  const approve = page.requests.find(r => r.url === '/rule/knowledge/k1/approve');
  assert.deepEqual(JSON.parse(approve.options.body), {version: 3, note: null});
  assert.equal(approve.options.headers['X-CSRF-TOKEN'], 'fixture');
  page.q('[data-knowledge-decision="retire"]').click();
  await tick();
  assert.deepEqual(JSON.parse(page.requests.find(r => r.url === '/rule/knowledge/k2/retire').options.body), {version: 5, note: 'Library upgraded'});
  assert.equal(page.navigations.length, 2);

  // Searching a picker renders results as text and adds a chosen item by name, not by typed ID.
  const repoSearch = page.q('[data-knowledge-picker="repositories"] [data-picker-search]');
  repoSearch.value = 'pay';
  repoSearch.dispatchEvent(new page.w.Event('input', {bubbles: true}));
  await new Promise(resolve => setTimeout(resolve, 300));
  await tick();
  const result = page.q('[data-knowledge-picker="repositories"] [data-picker-results] li');
  assert.equal(result.querySelector('img'), null);
  assert.match(result.textContent, /<img src=x onerror=alert\(1\)> payments-api/);
  assert.match(page.requests.find(r => r.url.startsWith('/rules/knowledge/options/repositories')).url, /search=pay/);
  result.querySelector('button').click();
  assert.equal(page.q('[data-knowledge-picker="repositories"] [data-picker-selected] li').dataset.pickerValue, '42');

  // Evidence searches are limited to the chosen rules.
  const evidenceSearch = page.q('[data-knowledge-picker="evidence"] [data-picker-search]');
  evidenceSearch.value = 'enc';
  evidenceSearch.dispatchEvent(new page.w.Event('input', {bubbles: true}));
  await new Promise(resolve => setTimeout(resolve, 300));
  await tick();
  assert.match(page.requests.find(r => r.url.startsWith('/rules/knowledge/options/review')).url, /ruleIds=7/);

  // The proposal is built from the chosen items; server validation messages are shown.
  page.q('[data-knowledge-statement]').value = 'Encode.forHtml escapes HTML output';
  page.q('[data-knowledge-language]').value = 'java';
  page.q('[data-knowledge-library]').value = 'OWASP Java Encoder';
  page.q('[data-knowledge-versions]').value = '1.2.x';
  page.q('[data-knowledge-cwes]').value = 'CWE-79, ';
  page.q('[data-knowledge-form]').dispatchEvent(new page.w.Event('submit', {bubbles: true, cancelable: true}));
  await tick();
  const proposed = JSON.parse(page.requests.find(r => r.url === '/rule/knowledge' && r.options.method).options.body);
  assert.deepEqual(proposed, {kind: 'SANITIZER', statement: 'Encode.forHtml escapes HTML output', language: 'java',
    library: 'OWASP Java Encoder', versionRange: '1.2.x', allRepositories: false, repositoryIds: [42], ruleIds: [7],
    cwes: ['CWE-79'], evidence: [{type: 'review', id: 'r-55'}], reviewBy: null});
  assert.equal(page.navigations.at(-1), '/rules/knowledge?status=PROPOSED');

  page.q('[data-knowledge-statement]').value = 'short';
  page.q('[data-knowledge-form]').dispatchEvent(new page.w.Event('submit', {bubbles: true, cancelable: true}));
  await tick();
  assert.match(page.q('[data-knowledge-status]').textContent, /Statement must be 10 to 300 characters/);

  // Removing a chosen item takes it out of the proposal.
  page.q('[data-knowledge-picker="rules"] [data-picker-remove]').click();
  assert.equal(page.q('[data-knowledge-picker="rules"] [data-picker-selected] li'), null);
  console.log('Knowledge page: CSRF decisions, safe picker results, name-based proposal, rule-scoped evidence and errors passed');
}
async function prefilledProposalOpensItsDialog() {
  const dom = new JSDOM(`<body><section data-knowledge-page data-csrf-header="X" data-csrf-token="t">
    <p data-knowledge-status></p>
    <div data-knowledge-propose data-open-on-load="true"><form data-knowledge-form><p data-knowledge-status></p></form></div>
  </section></body>`, {runScripts: 'dangerously'});
  const w = dom.window;
  let opened = 0;
  w.customElements.define('md-dialog', class extends w.HTMLElement {});
  w.document.querySelector('[data-knowledge-propose]').show = () => { opened++; };
  w.eval(fs.readFileSync(path.join(resources, 'static/scripts/knowledge-page.js'), 'utf8'));
  await tick();
  assert.equal(opened, 1, 'a prefilled rule or review opens the proposal dialog');
  console.log('Knowledge page: a prefilled proposal opens its dialog');
}

main().then(prefilledProposalOpensItsDialog).catch(error => { console.error(error); process.exitCode = 1; });

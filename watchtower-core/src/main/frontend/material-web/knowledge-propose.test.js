const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const resources = path.resolve(__dirname, '../../resources');
const script = fs.readFileSync(path.join(resources, 'static/scripts/knowledge-page.js'), 'utf8');
const template = fs.readFileSync(path.join(resources, 'templates/rules/knowledge.html'), 'utf8');

// The real Propose dialog, so the script and the template cannot drift apart.
const match = template.match(/<md-dialog id="knowledgeProposeDialog"[\s\S]*?<\/md-dialog>/);
assert.ok(match, 'the Propose dialog is missing from knowledge.html');

function ok(body) { return {ok: true, status: 200, json: async () => body}; }
function fail(status, body) { return {ok: false, status, json: async () => body}; }
const settle = async () => { for (let i = 0; i < 8; i += 1) await new Promise((resolve) => setTimeout(resolve, 0)); };

async function load(respond) {
  const dom = new JSDOM(`<body><section data-knowledge-page data-csrf-header="X-CSRF-TOKEN" data-csrf-token="fixture">${match[0]}</section></body>`,
    {runScripts: 'dangerously', url: 'https://watchtower.example/rules/knowledge'});
  const w = dom.window;
  // JSDOM does not implement the Material fields; give them the empty values the real ones start with.
  // A select is left unset here, as the real one is when it upgrades before its options: the page script must fill it.
  w.document.querySelectorAll('md-outlined-text-field').forEach((field) => { field.value = field.getAttribute('value') || ''; });
  w.document.querySelectorAll('md-outlined-select').forEach((select) => { select.value = ''; });
  w.document.querySelectorAll('md-checkbox').forEach((box) => { box.checked = false; });
  // Nothing is prefilled: the server renders those chips only for a rule or review link, and th:if is inert here.
  w.document.querySelectorAll('[data-picker-selected] li').forEach((chip) => chip.remove());
  const calls = [];
  const navigations = [];
  w.fetch = async (url, options = {}) => {
    const call = {url, method: options.method || 'GET', headers: options.headers || {}, body: options.body ? JSON.parse(options.body) : null};
    calls.push(call);
    return respond(call);
  };
  // The search delay is run at once, and navigation is recorded instead of followed.
  w.setTimeout = (fn) => { Promise.resolve().then(fn); return 1; };
  w.WatchtowerKnowledgeNavigate = (target) => navigations.push(target);
  w.eval(script);
  const q = (selector) => w.document.querySelector(selector);
  const search = async (picker, text) => {
    const field = q(`[data-knowledge-picker="${picker}"] [data-picker-search]`);
    field.value = text;
    field.dispatchEvent(new w.Event('input', {bubbles: true}));
    await settle();
  };
  return {w, calls, navigations, q, search};
}

async function main() {
  // The dialog is the shape that was approved: fields, one scope disclosure, the AI button beside the evidence.
  const page = await load(() => ok({content: []}));
  assert.ok(page.q('[data-knowledge-picker="evidence"] [data-ai-helper="knowledgeDraft"] [data-knowledge-draft]'), 'the AI button sits with the evidence');
  assert.ok(page.q('details.wt-form-disclosure[data-knowledge-scope] [data-knowledge-picker="repositories"]'), 'repositories sit behind the scope line');
  assert.ok(page.q('details.wt-form-disclosure[data-knowledge-scope] [data-knowledge-picker="rules"]'));
  assert.ok(page.q('details.wt-form-disclosure[data-knowledge-scope] [data-knowledge-cwes]'));
  assert.equal(page.q('details[data-knowledge-scope]').hasAttribute('open'), false, 'closed until something needs it');
  assert.equal(page.q('form [data-knowledge-status]').textContent, '', 'no note until there is something to say');
  // A Material select shows nothing and reads as empty unless its value is set, and the search asks for that type.
  assert.equal(page.q('[data-picker-type]').getAttribute('value'), 'review', 'the evidence type starts on a real choice');
  assert.equal(page.q('[data-knowledge-kind]').getAttribute('value'), 'SANITIZER', 'the kind starts on a real choice');
  assert.equal(page.q('[data-knowledge-scope-summary]').textContent, 'Choose repositories');
  assert.ok(page.q('[data-knowledge-scope-summary]').classList.contains('wt-tone-warning'));
  page.w.close();

  // Search matches are listed with an icon button; adding one makes a chip; the chip's icon removes it.
  const results = {
    review: [{id: 'r1', label: 'Accepted review: SqlConcatenation', preview: 'Sanitizer'}],
    repositories: [{id: '7', label: 'payments-api'}],
    rules: [{id: '3', label: 'AvoidConcatenatedSql'}]
  };
  const picking = await load((call) => {
    if (call.method === 'POST') return ok({});
    const kind = call.url.split('/rules/knowledge/options/')[1].split('?')[0];
    return ok({content: results[kind] || []});
  });
  assert.equal(picking.q('[data-picker-type]').value, 'review', 'the page fills a select that came up empty with its declared value');
  assert.equal(picking.q('[data-knowledge-kind]').value, 'SANITIZER');
  await picking.search('evidence', 'sql');
  assert.match(picking.calls[0].url, /^\/rules\/knowledge\/options\/review\?search=sql$/);
  const first = picking.q('[data-knowledge-picker="evidence"] [data-picker-results] li');
  assert.match(first.textContent, /Accepted review: SqlConcatenation/);
  const add = first.querySelector('button.wt-icon-action[aria-label="Add Accepted review: SqlConcatenation"]');
  assert.ok(add, 'an icon button adds it');
  assert.equal(add.querySelector('.material-icons').textContent, 'add');
  add.click();
  const evidence = picking.q('[data-knowledge-picker="evidence"] [data-picker-selected] li');
  assert.ok(evidence.classList.contains('wt-mini-chip'), 'a chosen item is a chip');
  assert.equal(evidence.dataset.pickerValue, 'r1');
  assert.equal(evidence.dataset.pickerType, 'review');
  assert.equal(evidence.querySelector('.material-icons').textContent, 'rate_review');
  assert.equal(picking.q('[data-knowledge-picker="evidence"] [data-picker-results]').children.length, 0, 'the matches are cleared once one is added');

  // Adding the same match twice makes one chip.
  await picking.search('evidence', 'sql');
  picking.q('[data-knowledge-picker="evidence"] [data-picker-results] button').click();
  assert.equal(picking.w.document.querySelectorAll('[data-knowledge-picker="evidence"] [data-picker-selected] li').length, 1);

  // The scope line says what is set, and stops warning once a repository is chosen.
  await picking.search('repositories', 'pay');
  picking.q('[data-knowledge-picker="repositories"] [data-picker-results] button').click();
  await picking.search('rules', 'avoid');
  picking.q('[data-knowledge-picker="rules"] [data-picker-results] button').click();
  const summary = picking.q('[data-knowledge-scope-summary]');
  assert.equal(summary.textContent, '1 repository · 1 rule');
  assert.equal(summary.classList.contains('wt-tone-warning'), false);
  picking.q('[data-knowledge-cwes]').value = 'CWE-89, CWE-564';
  picking.q('[data-knowledge-cwes]').dispatchEvent(new picking.w.Event('input', {bubbles: true}));
  assert.equal(summary.textContent, '1 repository · 1 rule · 2 CWEs');
  picking.q('[data-knowledge-picker="repositories"] [data-picker-remove]').click();
  assert.equal(summary.textContent, '1 rule · 2 CWEs');
  assert.ok(summary.classList.contains('wt-tone-warning'), 'no repository again');
  const everything = picking.q('[data-knowledge-all-repositories]');
  everything.checked = true;
  everything.dispatchEvent(new picking.w.Event('change', {bubbles: true}));
  assert.equal(summary.textContent, 'All repositories · 1 rule · 2 CWEs');
  assert.equal(summary.classList.contains('wt-tone-warning'), false);

  // Proposing sends what the form holds, in the same shape as before the redesign.
  everything.checked = false;
  await picking.search('repositories', 'pay');
  picking.q('[data-knowledge-picker="repositories"] [data-picker-results] button').click();
  picking.q('[data-knowledge-kind]').value = 'SANITIZER';
  picking.q('[data-knowledge-statement]').value = '  Encode.forHtml escapes HTML output  ';
  picking.q('[data-knowledge-language]').value = 'java';
  picking.q('[data-knowledge-library]').value = 'OWASP Java Encoder';
  picking.q('[data-knowledge-versions]').value = '1.2.x';
  picking.q('[data-knowledge-review-by]').value = '';
  picking.q('[data-knowledge-form]').dispatchEvent(new picking.w.Event('submit', {bubbles: true, cancelable: true}));
  await settle();
  const post = picking.calls.find((c) => c.method === 'POST');
  assert.equal(post.url, '/rule/knowledge');
  assert.equal(post.headers['X-CSRF-TOKEN'], 'fixture');
  assert.deepEqual(post.body, {kind: 'SANITIZER', statement: 'Encode.forHtml escapes HTML output', language: 'java', library: 'OWASP Java Encoder',
    versionRange: '1.2.x', allRepositories: false, repositoryIds: [7], ruleIds: [3], cwes: ['CWE-89', 'CWE-564'],
    evidence: [{type: 'review', id: 'r1'}], reviewBy: null});
  assert.deepEqual(picking.navigations, ['/rules/knowledge?status=PROPOSED'], 'it moves on to the proposals');
  picking.w.close();

  // A refusal from the server is written in the dialog's own note and scrolled into view, not left above a scrolled form.
  const refusing = await load(() => fail(400, {error: 'Choose at least one repository.'}));
  let scrolled = 0;
  refusing.q('form [data-knowledge-status]').scrollIntoView = () => { scrolled += 1; };
  refusing.q('[data-knowledge-statement]').value = 'x';
  refusing.q('[data-knowledge-language]').value = 'java';
  refusing.q('[data-knowledge-library]').value = 'lib';
  refusing.q('[data-knowledge-versions]').value = '1.x';
  refusing.q('[data-knowledge-form]').dispatchEvent(new refusing.w.Event('submit', {bubbles: true, cancelable: true}));
  await settle();
  assert.equal(refusing.q('form [data-knowledge-status]').textContent, 'Choose at least one repository.');
  assert.equal(scrolled, 1);
  refusing.w.close();
  console.log('knowledge-propose.test.js passed');
}

main().catch((error) => { console.error(error); process.exit(1); });

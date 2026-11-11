const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const resources = path.resolve(__dirname, '../../resources');
const helpers = fs.readFileSync(path.join(resources, 'static/scripts/ai-helpers.js'), 'utf8');
const template = fs.readFileSync(path.join(resources, 'templates/rules/knowledge.html'), 'utf8');

// The real Propose dialog, so the script and the template cannot drift apart.
const match = template.match(/<md-dialog id="knowledgeProposeDialog"[\s\S]*?<\/md-dialog>/);
assert.ok(match, 'the Propose dialog is missing from knowledge.html');
const DIALOG = match[0];

const page = `<!doctype html><body>
  <wt-assistant-drawer data-csrf-header="X-CSRF-TOKEN" data-csrf-token="fixture"></wt-assistant-drawer>${DIALOG}</body>`;

function ok(body) { return {ok: true, status: 200, json: async () => body}; }
function fail(status, body) { return {ok: false, status, json: async () => body}; }
const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

async function load(flags, respond) {
  const dom = new JSDOM(page, {runScripts: 'dangerously', url: 'https://watchtower.example/rules/knowledge'});
  const w = dom.window;
  const calls = [];
  w.fetch = async (url, options = {}) => {
    const call = {url, method: options.method || 'GET', headers: options.headers || {}, body: options.body ? JSON.parse(options.body) : null};
    calls.push(call);
    if (url === '/assistant/helpers') return ok(flags);
    return respond(call);
  };
  w.eval(helpers);
  w.document.dispatchEvent(new w.Event('DOMContentLoaded'));
  await settle();
  const q = (selector) => w.document.querySelector(selector);
  const choose = async (type, id) => {
    const li = w.document.createElement('li');
    li.dataset.pickerValue = id;
    li.dataset.pickerType = type;
    q('[data-knowledge-picker="evidence"] [data-picker-selected]').appendChild(li);
    await settle();
  };
  return {w, calls, q, choose, draftCalls: () => calls.filter((c) => c.url === '/assistant/knowledge-draft')};
}

const DRAFT = {state: 'OK', reason: 'The review says Encode.forHtml is a sanitizer.', fields: {kind: 'SANITIZER',
  statement: 'Encode.forHtml escapes HTML output, so it makes a value safe for an HTML body.', language: 'java', library: 'OWASP Java Encoder',
  version_range: '1.2.x', cwes: ['CWE-79', 'CWE-116']}};

async function main() {
  // Not offered to someone who cannot use it.
  const off = await load({knowledgeDraft: false}, () => ok({}));
  assert.equal(off.q('[data-ai-helper="knowledgeDraft"]'), null);
  off.w.close();

  // The button waits for evidence: it fills the form from what is chosen, so nothing chosen means nothing to draft from.
  const drafting = await load({knowledgeDraft: true}, () => ok(DRAFT));
  const button = drafting.q('[data-knowledge-draft]');
  assert.equal(drafting.q('[data-ai-helper="knowledgeDraft"]').hidden, false);
  assert.equal(button.disabled, true, 'no evidence yet');
  await drafting.choose('review', 'r1');
  assert.equal(button.disabled, false);

  // A field the person already typed stays when the assistant has nothing for it; the rest are filled.
  const empty = await load({knowledgeDraft: true}, () => ok({state: 'OK', reason: '', fields: Object.assign({}, DRAFT.fields, {library: '', version_range: ''})}));
  await empty.choose('review', 'r1');
  empty.q('[data-knowledge-library]').value = 'typed by hand';
  empty.q('[data-knowledge-draft]').click();
  await settle();
  assert.equal(empty.q('[data-knowledge-library]').value, 'typed by hand');
  assert.equal(empty.q('[data-knowledge-statement]').value, DRAFT.fields.statement);
  empty.w.close();

  // Drafting sends only the chosen references with CSRF, fills every form field, and says it is a draft to check.
  await drafting.choose('missed_case', 'm1');
  button.click();
  await settle();
  const call = drafting.draftCalls()[0];
  assert.equal(call.method, 'POST');
  assert.equal(call.headers['X-CSRF-TOKEN'], 'fixture');
  assert.deepEqual(call.body, {evidence: [{type: 'review', id: 'r1'}, {type: 'missed_case', id: 'm1'}]});
  assert.equal(drafting.q('[data-knowledge-kind]').value, 'SANITIZER');
  assert.equal(drafting.q('[data-knowledge-statement]').value, DRAFT.fields.statement);
  assert.equal(drafting.q('[data-knowledge-language]').value, 'java');
  assert.equal(drafting.q('[data-knowledge-library]').value, 'OWASP Java Encoder');
  assert.equal(drafting.q('[data-knowledge-versions]').value, '1.2.x');
  assert.equal(drafting.q('[data-knowledge-cwes]').value, 'CWE-79, CWE-116');
  const status = drafting.q('form [data-knowledge-status]').textContent;
  assert.match(status, /Drafted by the assistant/);
  assert.match(status, /Check every field before you propose/);
  assert.match(status, /Encode\.forHtml is a sanitizer/);
  assert.equal(button.disabled, false, 'it can be asked again');
  assert.equal(drafting.calls.filter((c) => c.method === 'POST' && c.url !== '/assistant/knowledge-draft').length, 0, 'it proposes nothing');
  drafting.w.close();

  // A refusal is explained and the form is left alone.
  const refused = await load({knowledgeDraft: true}, () => ok({state: 'BLOCKED', message: 'Evidence about rules that detect secrets is never sent to the assistant.'}));
  await refused.choose('review', 'r1');
  refused.q('[data-knowledge-statement]').value = 'mine';
  refused.q('[data-knowledge-draft]').click();
  await settle();
  assert.match(refused.q('form [data-knowledge-status]').textContent, /never sent to the assistant/);
  assert.equal(refused.q('[data-knowledge-statement]').value, 'mine');
  // Taking the evidence away ends the refusal: it was about the evidence that was chosen.
  const li = refused.w.document.querySelector('[data-picker-selected] li[data-picker-value="r1"]');
  li.remove();
  await settle();
  assert.equal(refused.q('form [data-knowledge-status]').textContent, '');
  refused.w.close();

  // Errors from the server (a used-up share, a bad choice) are shown as text.
  const failing = await load({knowledgeDraft: true}, () => fail(429, {message: 'The daily AI budget for knowledge drafts is used up; try again tomorrow.'}));
  await failing.choose('review', 'r1');
  failing.q('[data-knowledge-draft]').click();
  await settle();
  assert.match(failing.q('form [data-knowledge-status]').textContent, /used up/);
  assert.equal(failing.q('[data-knowledge-draft]').disabled, false);
  failing.w.close();

  // More than five pieces of evidence is explained locally and nothing is sent.
  const many = await load({knowledgeDraft: true}, () => ok(DRAFT));
  for (let i = 0; i < 6; i += 1) await many.choose('review', 'r' + i);
  many.q('[data-knowledge-draft]').click();
  await settle();
  assert.match(many.q('form [data-knowledge-status]').textContent, /at most 5/);
  assert.equal(many.draftCalls().length, 0);

  // Taking the evidence away disables the button again.
  many.q('[data-knowledge-picker="evidence"] [data-picker-selected]').replaceChildren();
  await settle();
  assert.equal(many.q('[data-knowledge-draft]').disabled, true);
  many.w.close();
  console.log('knowledge-draft.test.js passed');
}

main().catch((error) => { console.error(error); process.exit(1); });

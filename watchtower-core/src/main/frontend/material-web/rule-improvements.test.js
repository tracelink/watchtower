// Suggest a rule improvement (Improve board, 2026-10-22): plain-word evidence tiles, the empty state
// that keeps Next and Generate off, the before/after proposal, safe rendering and the edited save.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.join(__dirname, '../../resources/static/scripts/rule-improvements.js'), 'utf8');
const flush = async () => { for (let i = 0; i < 16; i++) await new Promise(r => setTimeout(r, 0)); };
const response = data => ({ok: true, json: async () => data});

const markup = (chatReady = 'true') => `<section data-rule-improvements data-rule-id="7" data-csrf-header="X-CSRF" data-csrf-token="csrf"
  data-can-modify="true" data-chat-ready="${chatReady}" data-candidates-url="/rules/7/candidates">
 <button data-improvement-step="1"><span data-improvement-step-state="1"></span></button>
 <button data-improvement-step="2"><span data-improvement-step-state="2"></span></button>
 <button data-improvement-step="3"><span data-improvement-step-state="3"></span></button>
 <p data-improvement-status></p>
 <section data-improvement-panel="1">
  <button data-improvement-days="7"></button><button data-improvement-days="30"></button><button data-improvement-days="90"></button>
  <details data-improvement-language-menu><summary><span data-improvement-language-label></span></summary>
   <input data-improvement-language><button data-improvement-language-clear></button><button data-improvement-language-apply></button></details>
  <div data-improvement-tiles></div>
  <div data-improvement-empty hidden></div>
  <span data-improvement-needs-evidence hidden></span><button data-improvement-next disabled></button>
 </section>
 <section data-improvement-panel="2" hidden>
  <textarea data-improvement-question></textarea><button data-improvement-cancel hidden></button><button data-improvement-generate disabled></button>
  <div data-improvement-review hidden><span data-improvement-outcome hidden></span><div data-improvement-proposal></div></div>
  <button data-improvement-use hidden></button>
 </section>
 <section data-improvement-panel="3" hidden>
  <div data-improvement-fields></div><input data-improvement-rationale>
  <a data-improvement-candidates href="/rules/7/candidates"><span></span>Open candidates</a><button data-improvement-save></button>
 </section>
</section>`;

const sample = (kind, revisionScope, total, currentTotal) => ({kind, revisionScope, total, selected: Math.min(total, 4), truncated: total > 4, currentTotal});
const emptySamples = [sample('TRUE_POSITIVE', 'CURRENT', 0, 0), sample('TRUE_POSITIVE', 'HISTORICAL_OR_UNKNOWN', 0, 0),
  sample('FALSE_POSITIVE', 'CURRENT', 0, 0), sample('FALSE_POSITIVE', 'HISTORICAL_OR_UNKNOWN', 0, 0),
  sample('UNKNOWN', 'CURRENT', 0, 0), sample('UNKNOWN', 'HISTORICAL_OR_UNKNOWN', 0, 0),
  sample('SAVED_REVIEWS', 'MIXED', 0, 0), sample('MISSED_CASES', 'MIXED', 0, 0)];
const rule = {id: 'rule/7', revision: 'base', data: {definition: {name: '<img src=x onerror=bad()>', regexPattern: 'unsafe|risky'}}};

function page(evidence, chatReady) {
  const dom = new JSDOM(markup(chatReady), {url: 'https://watchtower.test/rules/7/improvements', runScripts: 'outside-only'});
  const w = dom.window, requests = [];
  w.crypto.randomUUID = () => 'key-1';
  return {dom, w, requests, evidence};
}

(async function () {
  // 1. No reviewed findings: the empty state shows, Next and Generate stay off, no codes appear.
  {
    const {dom, w, requests} = page();
    w.fetch = async (url, opts) => { requests.push({url, opts}); return response({baseRevision: 'base', samples: emptySamples, references: [rule], editableFields: {}}); };
    w.eval(script); await flush();
    const text = w.document.body.textContent;
    assert.equal(w.document.querySelectorAll('[data-improvement-tile]').length, 5);
    for (const label of ['Confirmed real', 'False alarm', 'Unsure', 'Saved reviews', 'Missed cases']) assert.match(text, new RegExp(label));
    assert.doesNotMatch(text, /TRUE_POSITIVE|HISTORICAL_OR_UNKNOWN|MVP/);
    assert.match(text, /0 this version · 0 older/);
    assert.equal(w.document.querySelector('[data-improvement-empty]').hidden, false);
    assert.equal(w.document.querySelector('[data-improvement-needs-evidence]').hidden, false);
    assert.equal(w.document.querySelector('[data-improvement-next]').disabled, true);
    assert.equal(w.document.querySelector('[data-improvement-generate]').disabled, true);
    assert.equal(w.document.querySelector('[data-improvement-step-state="1"]').textContent, '0 reviewed');
    assert.equal(w.document.querySelector('[data-improvement-step-state="2"]').textContent, 'Needs evidence');
    w.document.querySelector('[data-improvement-step="2"]').click();
    assert.equal(w.document.querySelector('[data-improvement-panel="2"]').hidden, true, 'locked step must not open');
    w.document.querySelector('[data-improvement-days="30"]').click(); await flush();
    assert.match(requests.at(-1).url, /days=30/);
    dom.window.close();
  }

  // 2. Evidence → proposal → edited draft save.
  {
    const {dom, w, requests} = page();
    const samples = emptySamples.map(s => s.kind === 'FALSE_POSITIVE' && s.revisionScope === 'CURRENT' ? sample('FALSE_POSITIVE', 'CURRENT', 3, 3)
      : s.kind === 'SAVED_REVIEWS' ? sample('SAVED_REVIEWS', 'MIXED', 2, 1) : s);
    const evidence = {baseRevision: 'base', samples, editableFields: {regexPattern: {type: 'string', nullable: false}},
      references: [rule, {id: 'health/7', revision: 'base', data: {}}, {id: 'feedback/one', revision: 'base', data: {judgment: 'FALSE_POSITIVE'}}, {id: 'review/r1', revision: 'base', data: {}}]};
    const ready = {id: 'proposal', version: 1, status: 'READY', turnStatus: 'COMPLETED', turnId: 'turn', stale: false, baseRevision: 'base',
      evidenceReferences: [{id: 'review/r1', revision: 'abcdef1234', contentHash: 'hash'}],
      proposal: {outcome: 'PROPOSED_CHANGE', problem: 'Flags <b>suppressed</b> classes', expectedBenefit: 'Fewer false alarms',
        changes: {regexPattern: 'risky'}, citations: ['review/r1'], regressions: ['May miss subclasses'], limitations: []}};
    w.fetch = async (url, opts) => {
      requests.push({url, opts});
      if (url.includes('/evidence?')) return response(evidence);
      if (url.endsWith('/candidate')) return response({candidateId: 'candidate-9'});
      if (url === '/assistant/turn/turn') return response({answer: '{"examples":["<script>example</script>"],"proposedTests":["Review first"]}'});
      return response(ready);
    };
    w.eval(script); await flush();
    assert.match(w.document.body.textContent, /3 this version · 0 older/);
    assert.match(w.document.body.textContent, /1 this version · 1 older/);
    assert.equal(w.document.querySelector('[data-improvement-empty]').hidden, true);
    assert.equal(w.document.querySelector('[data-improvement-next]').disabled, false);
    w.document.querySelector('[data-improvement-next]').click();
    assert.equal(w.document.querySelector('[data-improvement-panel="2"]').hidden, false);
    w.document.querySelector('[data-improvement-question]').value = 'Skip suppressed classes';
    w.document.querySelector('[data-improvement-generate]').click(); await flush();
    const generate = requests.find(r => r.url === '/rules/7/improvements' && r.opts.method === 'POST');
    const body = JSON.parse(generate.opts.body);
    assert.deepEqual(body.evidenceIds, ['feedback/one', 'review/r1']);
    assert.equal(body.idempotencyKey, 'key-1');
    assert.equal(generate.opts.headers['X-CSRF'], 'csrf');
    const proposal = w.document.querySelector('[data-improvement-proposal]');
    assert.match(proposal.textContent, /Current rule · Matching pattern/);
    assert.match(proposal.textContent, /unsafe\|risky/);
    assert.match(proposal.textContent, /Saved review \(cited\)/);
    assert.match(proposal.textContent, /Risk: May miss subclasses/);
    assert.match(proposal.textContent, /Illustrative examples and tests \(not run\)/);
    assert.equal(w.document.querySelectorAll('script,img,b').length, 0, 'proposal text must render as text');
    assert.equal(proposal.querySelector('a[href*="reviewId=r1"]') !== null, true);
    assert.equal(w.document.querySelector('[data-improvement-use]').hidden, false);
    w.document.querySelector('[data-improvement-use]').click();
    assert.equal(w.document.querySelector('[data-improvement-panel="3"]').hidden, false);
    const field = w.document.querySelector('[data-improvement-fields] [data-field="regexPattern"]');
    assert.equal(field.value, 'risky', 'string fields edit as plain text');
    field.value = 'risky|reviewed';
    w.document.querySelector('[data-improvement-rationale]').value = 'Human accepted';
    w.document.querySelector('[data-improvement-save]').click(); await flush();
    const save = requests.find(r => r.url.endsWith('/candidate'));
    assert.deepEqual(JSON.parse(save.opts.body), {version: 1, baseRevision: 'base', changes: {regexPattern: 'risky|reviewed'}, rationale: 'Human accepted', reviewId: null});
    assert.equal(w.document.querySelector('[data-improvement-candidates]').getAttribute('href'), '/rules/7/candidates?candidate=candidate-9');
    assert.equal(w.document.querySelector('[data-improvement-step-state="3"]').textContent, 'Saved');
    assert.match(w.document.querySelector('[data-improvement-status]').textContent, /Draft saved/);
    dom.window.close();
  }

  // 3. Chat not ready: evidence exists but Generate stays off and the step says why.
  {
    const {dom, w} = page(undefined, 'false');
    const samples = emptySamples.map(s => s.kind === 'UNKNOWN' && s.revisionScope === 'CURRENT' ? sample('UNKNOWN', 'CURRENT', 1, 1) : s);
    w.fetch = async () => response({baseRevision: 'base', samples, references: [rule], editableFields: {}});
    w.eval(script); await flush();
    assert.equal(w.document.querySelector('[data-improvement-generate]').disabled, true);
    assert.equal(w.document.querySelector('[data-improvement-step-state="2"]').textContent, 'Chat not ready');
    dom.window.close();
  }
  console.log('Rule improvements: plain-word evidence, empty state, before/after proposal and edited draft save passed');
})().catch(e => { console.error(e); process.exitCode = 1; });

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
const template = fs.readFileSync(path.join(resources, 'templates/fragments/container.html'), 'utf8');
const drawer = template.match(/<wt-assistant-drawer[\s\S]*?<\/wt-assistant-drawer>/)[0];

/** Opens the drawer on a page and sends one question; returns the body sent to /assistant/turn. */
async function ask(page, contextCards, triggerSelector, preview) {
  preview = preview || {state: 'OK', label: 'ImmutableField · ImageSecurityReport.java:12', title: 'Finding · ImmutableField', lines: ['Medium · wt-test', 'Not reviewed · no AI assessment yet']};
  const dom = new JSDOM(`<body>${drawer}<main id="content"><h1 class="page-title">Scan report</h1>${page}</main></body>`, {url: 'https://watchtower.example/scan/report/12', runScripts: 'dangerously'});
  const w = dom.window;
  const requests = [];
  w.fetch = async (url, options = {}) => {
    requests.push({url, options});
    if (url === '/assistant/status') return {ok: true, json: async () => ({ready: true})};
    if (url === '/assistant/models') return {ok: true, json: async () => ({models: [{id: 'm', efforts: ['low']}], defaultModel: 'm', defaultEffort: 'low', retentionDays: 14, rulesetActions: false, contextCards})};
    if (url === '/assistant/budget') return {ok: true, json: async () => ({usedCostMicros: 0, dailyCostMicros: 1000000})};
    if (url === '/assistant/active') return {ok: true, json: async () => []};
    if (url === '/assistant/context') return {ok: true, json: async () => preview};
    if (url === '/assistant/turn') return {ok: true, json: async () => ({sessionId: 's', turnId: 't', status: 'QUEUED', context: 'OK'})};
    return {ok: true, json: async () => ({status: 'QUEUED'})};
  };
  w.eval(fs.readFileSync(path.join(resources, 'static/scripts/assistant.js'), 'utf8'));
  const component = w.document.querySelector('wt-assistant-drawer');
  component.dataset.csrfHeader = 'X-CSRF-TOKEN'; component.dataset.csrfToken = 'fixture';
  await component.open(undefined, triggerSelector ? w.document.querySelector(triggerSelector) : undefined);
  component.input.value = 'Is this a false positive?';
  await component.submit();
  const body = JSON.parse(requests.find(r => r.url === '/assistant/turn').options.body);
  const state = component.contextState;
  const chipEl = component.querySelector('[data-assistant-context-chip]');
  const chipView = {hidden: chipEl.hidden, label: component.querySelector('[data-assistant-context-label]').textContent, icon: component.querySelector('[data-assistant-context-icon]').textContent, tip: chipEl.getAttribute('data-tip'), bad: chipEl.classList.contains('wt-mini-chip--bad')};
  component.stopStream(); clearTimeout(component.timer); dom.window.close();
  return {body, state, chipView};
}

/** Draws one assistant answer in the drawer and returns what it shows. */
function answer(body, result) {
  const dom = new JSDOM(`<body>${drawer}<main id="content"></main></body>`, {url: 'https://watchtower.example/scan/report/12', runScripts: 'dangerously'});
  const w = dom.window;
  w.eval(fs.readFileSync(path.join(resources, 'static/scripts/assistant.js'), 'utf8'));
  const component = w.document.querySelector('wt-assistant-drawer');
  const section = component.message('assistant', body, 'turn-1', result);
  const view = {
    chips: [...section.querySelectorAll('.wt-assistant-cited .wt-mini-chip')].map(c => [c.textContent.trim().replace(/^\w+/, m => m), c.getAttribute('data-tip')]),
    blocked: section.querySelector('.wt-assistant-blocked') && section.querySelector('.wt-assistant-blocked').textContent,
    note: section.querySelector('.wt-assistant-note') && section.querySelector('.wt-assistant-note').textContent
  };
  dom.window.close();
  return view;
}

async function main() {
  // Answers about a finding say they are only a suggestion; reading a stored assessment says it is advice and counts as seen.
  const plain = answer('It looks like a likely true positive.', {about: {kind: 'finding', state: 'OK'}, activity: []});
  assert.deepEqual(plain.chips.map(c => c[0]), ['lightbulbSuggestion only']);
  assert.match(plain.chips[0][1], /You record true or false positive yourself/);
  const advice = answer('A stored assessment exists.', {about: {kind: 'finding', state: 'OK'}, activity: [{tool: 'get_finding_assessment', status: 'read'}]});
  assert.deepEqual(advice.chips.map(c => c[0]), ['lightbulbSuggestion only', 'psychologyAI advice, not a verdict', 'visibilityAI opinion seen']);
  assert.match(advice.chips[2][1], /left out of the blind AI-vs-human agreement number/);
  // Asking for an assessment that does not exist (none made yet, or the feature is off) shows no opinion, so it does not say one was seen.
  const noOpinion = answer('There is no stored assessment.', {about: {kind: 'finding', state: 'OK'}, activity: [{tool: 'get_finding_assessment', status: 'read', opinion: false}]});
  assert.deepEqual(noOpinion.chips.map(c => c[0]), ['lightbulbSuggestion only']);
  const shown = answer('A stored assessment exists.', {about: {kind: 'finding', state: 'OK'}, activity: [{tool: 'get_finding_assessment', status: 'read', opinion: true}]});
  assert.deepEqual(shown.chips.map(c => c[0]), ['lightbulbSuggestion only', 'psychologyAI advice, not a verdict', 'visibilityAI opinion seen']);
  assert.deepEqual(answer('How do rulesets work?', {about: {kind: 'rule', state: 'OK'}, activity: [{tool: 'get_rule', status: 'read'}]}).chips, [], 'no chips when nothing about a finding was shared');
  const blocked = answer('Blocked: secret finding. Findings of secret rules are never sent to the AI.', {about: {kind: 'finding', state: 'BLOCKED'}});
  assert.match(blocked.blocked, /Blocked: secret finding/);
  assert.match(blocked.note, /No model was called/);
  assert.deepEqual(blocked.chips, [], 'a blocked finding is not a suggestion');

  const page = '<div data-assistant-kind="finding" data-assistant-scan-type="pull_request" data-assistant-scan-id="12" data-assistant-finding-key="9" data-assistant-label="IGNORED">x</div>';
  // Context cards on: ids only, and the message is exactly what was typed.
  const on = await ask(page, true);
  assert.deepEqual(on.body.context, {v: 1, kind: 'finding', ids: {scanType: 'pull_request', scanId: 12, findingKey: '9'}});
  assert.equal(on.body.message, 'Is this a false positive?', 'no page text in the message');
  assert.equal(on.state, 'OK', 'the server says how the page was understood');
  // Off: today's behaviour, the page name travels as a message prefix and no ids are sent.
  const off = await ask(page, false);
  assert.equal('context' in off.body, false);
  assert.match(off.body.message, /^\[Looking at: Scan report · \/scan\/report\/12\]\n\nIs this a false positive\?$/);
  // A page without a subject sends no context, and bad ids are dropped rather than guessed.
  const none = await ask('<p>nothing</p>', true);
  assert.equal('context' in none.body, false);
  const bad = await ask('<div data-assistant-kind="finding" data-assistant-scan-id="-3" data-assistant-repo-id="abc" data-assistant-rule-id="7.5">x</div>', true);
  assert.deepEqual(bad.body.context, {v: 1, kind: 'finding', ids: {}});
  // Pages that name no ids send only their kind; a scan type's metrics also name the scan type.
  const home = await ask('<div data-assistant-kind="home">x</div>', true);
  assert.deepEqual(home.body.context, {v: 1, kind: 'home', ids: {}});
  const metrics = await ask('<span hidden data-assistant-kind="metrics" data-assistant-scan-type="container"></span>', true);
  assert.deepEqual(metrics.body.context, {v: 1, kind: 'metrics', ids: {scanType: 'container'}});
  // Moving through findings asks the server once, for the one the person stops on, and an open() that overlaps is not left waiting.
  {
    const dom = new JSDOM(`<body>${drawer}<main id="content"><div data-scan-type="pull_request" data-scan-id="58"></div><ul><li data-finding-item class="is-selected" data-feedback-key="1" data-title="A">a</li></ul></main></body>`, {url: 'https://watchtower.example/scan/report/58', runScripts: 'dangerously'});
    const w = dom.window; let previews = 0;
    w.fetch = async (url) => {
      if (url === '/assistant/context') { previews++; return {ok: true, json: async () => ({state: 'OK', label: 'preview ' + previews, title: 't', lines: []})}; }
      if (url === '/assistant/status') return {ok: true, json: async () => ({ready: true})};
      if (url === '/assistant/models') return {ok: true, json: async () => ({models: [{id: 'm', efforts: ['low']}], defaultModel: 'm', defaultEffort: 'low', retentionDays: 14, rulesetActions: false, contextCards: true})};
      if (url === '/assistant/budget') return {ok: true, json: async () => ({usedCostMicros: 0, dailyCostMicros: 1000000, features: []})};
      return {ok: true, json: async () => []};
    };
    w.eval(fs.readFileSync(path.join(resources, 'static/scripts/assistant.js'), 'utf8'));
    const component = w.document.querySelector('wt-assistant-drawer');
    const opening = component.open();
    for (let i = 0; i < 5; i++) { w.document.dispatchEvent(new w.CustomEvent('wt:finding-selected')); await new Promise(resolve => setTimeout(resolve, 10)); }
    await Promise.race([opening, new Promise((_, reject) => setTimeout(() => reject(new Error('open() was left waiting')), 2000))]);
    await new Promise(resolve => setTimeout(resolve, 250));
    assert.equal(previews, 1, 'one request for a burst of selections');
    dom.window.close();
  }
  // A page that refreshes itself on a timer (Home polls) does not make the assistant ask again for the same page.
  {
    const dom = new JSDOM(`<body>${drawer}<main id="content"><div data-scan-type="pull_request" data-scan-id="58"></div><ul><li data-finding-item class="is-selected" data-feedback-key="1" data-title="A">a</li><li data-finding-item data-feedback-key="2" data-title="B">b</li></ul></main></body>`, {url: 'https://watchtower.example/scan/report/58', runScripts: 'dangerously'});
    const w = dom.window; let previews = 0;
    w.fetch = async (url) => {
      if (url === '/assistant/context') { previews++; return {ok: true, json: async () => ({state: 'OK', label: 'preview ' + previews, title: 't', lines: []})}; }
      if (url === '/assistant/status') return {ok: true, json: async () => ({ready: true})};
      if (url === '/assistant/models') return {ok: true, json: async () => ({models: [{id: 'm', efforts: ['low']}], defaultModel: 'm', defaultEffort: 'low', retentionDays: 14, rulesetActions: false, contextCards: true})};
      if (url === '/assistant/budget') return {ok: true, json: async () => ({usedCostMicros: 0, dailyCostMicros: 1000000, features: []})};
      return {ok: true, json: async () => []};
    };
    w.eval(fs.readFileSync(path.join(resources, 'static/scripts/assistant.js'), 'utf8'));
    const component = w.document.querySelector('wt-assistant-drawer');
    await component.open();
    await new Promise(resolve => setTimeout(resolve, 250));
    assert.equal(previews, 1, 'asked once when opened');
    for (let i = 0; i < 10; i++) { w.document.body.dispatchEvent(new w.CustomEvent('htmx:afterSettle', {bubbles: true})); await new Promise(resolve => setTimeout(resolve, 10)); }
    await new Promise(resolve => setTimeout(resolve, 250));
    assert.equal(previews, 1, 'ten polls of an unchanged page ask nothing more');
    w.document.querySelectorAll('[data-finding-item]').forEach(li => li.classList.toggle('is-selected'));
    w.document.dispatchEvent(new w.CustomEvent('wt:finding-selected'));
    await new Promise(resolve => setTimeout(resolve, 250));
    assert.equal(previews, 2, 'a different finding is a different question and is asked');
    component.stopStream(); clearTimeout(component.timer); dom.window.close();
  }
  // The chip says how the server understood the page, in its own words, never page text.
  assert.equal(on.chipView.label, 'Looking at: ImmutableField · ImageSecurityReport.java:12');
  assert.equal(on.chipView.icon, 'visibility');
  assert.equal(on.chipView.tip, 'Finding · ImmutableField\nMedium · wt-test\nNot reviewed · no AI assessment yet\nBuilt by the server for you. Remove to ask about anything.');
  const secret = await ask(page, true, undefined, {state: 'BLOCKED', lines: []});
  assert.equal(secret.chipView.label, 'Secret finding');
  assert.equal(secret.chipView.icon, 'lock');
  assert.equal(secret.chipView.bad, true);
  assert.match(secret.chipView.tip, /never sent to the AI/);
  assert.doesNotMatch(secret.chipView.tip + secret.chipView.label, /ImmutableField|ImageSecurity/, 'nothing about the finding is shown');
  const gone = await ask(page, true, undefined, {state: 'UNAVAILABLE', lines: []});
  assert.equal(gone.chipView.label, 'Page not shared');
  assert.equal(gone.chipView.icon, 'visibility_off');
  assert.match(gone.chipView.tip, /Chat still works/);
  // Cards off: today's chip, from the page name.
  assert.match(off.chipView.label, /^Looking at: Scan report/);
  // The chosen finding in a report, not the page, is what the assistant is asked about.
  const report = '<div data-scan-type="pull_request" data-scan-id="58"></div><div data-assistant-kind="pull_request" data-assistant-scan-id="58"></div>'
    + '<ul><li data-finding-item data-feedback-key="101" data-title="Other">a</li><li data-finding-item class="is-selected" data-feedback-key="102" data-title="ImmutableField">b</li></ul>';
  const picked = await ask(report, true);
  assert.deepEqual(picked.body.context, {v: 1, kind: 'finding', ids: {scanType: 'pull_request', scanId: 58, findingKey: '102'}});
  // A page-level button for something else keeps priority over the list.
  const button = await ask(report + '<button data-assistant-kind="repository" data-assistant-repo-id="4">x</button>', true, '[data-assistant-repo-id]');
  assert.equal(button.body.context.kind, 'repository');
  // Upload findings are not described to the assistant.
  const upload = await ask(report.replace('pull_request', 'upload'), true);
  assert.equal(upload.body.context.kind, 'pull_request');
  // The rule page names its rule, so the assistant is shown that rule and not just the page name.
  const ruleTemplate = require('node:fs').readFileSync(require('node:path').resolve(__dirname, '../../resources/templates/rules/rule-edit.html'), 'utf8');
  assert.match(ruleTemplate, /data-assistant-kind="rule"[^>]*th:attr="data-assistant-rule-id=\$\{activeRule\.id\}"|th:attr="data-assistant-rule-id=\$\{activeRule\.id\}"[^>]*data-assistant-kind="rule"/);
  const rulePage = await ask('<span hidden data-assistant-kind="rule" data-assistant-rule-id="1265"></span>', true);
  assert.deepEqual(rulePage.body.context, {v: 1, kind: 'rule', ids: {ruleId: 1265}});
  // An AWS Security Agent finding is not in the scan report the server rebuilds findings from, so the page is named instead of a finding that can never be found.
  const aws = await ask('<div data-scan-type="repository" data-scan-id="12"></div><ul><li data-finding-item class="is-selected" data-scanner-group="aws" data-feedback-key="051a665d" data-title="Privilege escalation">a</li></ul>', true);
  assert.equal(aws.body.context, undefined, 'no finding is asked about');
  assert.match(aws.body.message, /^\[Looking at: Scan report/);
  // A page's own instruction still travels with the page name, even when ids describe the page.
  const guided = await ask('<button data-assistant-kind="repository" data-assistant-repo-id="4" data-assistant-context="Keep this exact repository scope.">x</button>', true, '[data-assistant-context]');
  assert.deepEqual(guided.body.context, {v: 1, kind: 'repository', ids: {repoId: 4}});
  assert.match(guided.body.message, /^\[Looking at: .*Keep this exact repository scope\./);
  // A page the server cannot rebuild keeps the page name in the message instead of losing it.
  const unnamed = await ask('<p>nothing</p>', true);
  assert.match(unnamed.body.message, /^\[Looking at: Scan report/);
  // Share my draft: the designer's text goes with the next question only; a refused draft says why and is dropped.
  for (const refuse of [false, true]) {
    const dom = new JSDOM(`<body>${drawer}<main id="content"><div data-ai-draft-scope><textarea name="xpath">//Foo[@Public]</textarea><input name="name" value="AvoidPublicFields"></div></main></body>`, {url: 'https://watchtower.example/designer/pmd', runScripts: 'dangerously'});
    const w = dom.window; const sent = [];
    w.fetch = async (url, options = {}) => {
      if (url === '/assistant/status') return {ok: true, json: async () => ({ready: true})};
      if (url === '/assistant/models') return {ok: true, json: async () => ({models: [{id: 'm', efforts: ['low']}], defaultModel: 'm', defaultEffort: 'low', retentionDays: 14, rulesetActions: false, contextCards: true})};
      if (url === '/assistant/budget') return {ok: true, json: async () => ({usedCostMicros: 0, dailyCostMicros: 1000000, features: []})};
      if (url === '/assistant/active') return {ok: true, json: async () => []};
      if (url === '/assistant/turn') {
        sent.push(JSON.parse(options.body));
        return refuse ? {ok: false, status: 400, json: async () => ({error: 'This draft looks like it contains a secret, so it was not shared. Remove it and try again.'})}
          : {ok: true, json: async () => ({sessionId: 's', turnId: 't', status: 'QUEUED', context: 'NONE'})};
      }
      return {ok: true, json: async () => ({status: 'QUEUED'})};
    };
    w.eval(fs.readFileSync(path.join(resources, 'static/scripts/ai-helpers.js'), 'utf8'));
    w.eval(fs.readFileSync(path.join(resources, 'static/scripts/assistant.js'), 'utf8'));
    const component = w.document.querySelector('wt-assistant-drawer');
    component.dataset.csrfHeader = 'X-CSRF-TOKEN'; component.dataset.csrfToken = 'fixture';
    const cleared = []; w.document.addEventListener('wt:assistant-draft-cleared', () => cleared.push(true));
    await component.open();
    w.document.dispatchEvent(new w.CustomEvent('wt:assistant-draft', {detail: {on: true}}));
    const draftChip = component.querySelector('[data-assistant-draft-chip]');
    assert.equal(draftChip.hidden, false, 'the drawer says a draft is shared');
    component.input.value = 'Why does my rule miss it?';
    await component.submit();
    assert.equal(sent[0].draft, 'xpath: //Foo[@Public]\nname: AvoidPublicFields');
    assert.equal(draftChip.hidden, true, 'one question only: the chip goes once it is sent');
    assert.equal(cleared.length >= 1, true, 'the designer button is told');
    if (refuse) {
      assert.match(component.messages.textContent, /Draft not shared/);
      assert.match(component.messages.textContent, /looks like it contains a secret/);
      assert.equal(component.pendingSubmit, null, 'a refused draft is not retried');
      assert.equal(component.querySelector('.wt-assistant-message--user'), null, 'nothing was posted as asked');
    } else {
      assert.match(component.messages.querySelector('.wt-assistant-message--user').textContent, /Draft attached · 2 lines/);
      // The first answer finishes; the next question is asked fresh.
      component.stopStream(); clearTimeout(component.timer); component.busyState(false);
      component.input.value = 'And now?'; await component.submit();
      assert.equal('draft' in sent[1], false, 'the next question carries no draft');
    }
    component.stopStream(); clearTimeout(component.timer); dom.window.close();
  }
  console.log('Assistant page context ids, switch and message tests passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});

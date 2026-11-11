const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
const template = fs.readFileSync(path.join(resources, 'templates/fragments/container.html'), 'utf8');
const drawer = template.match(/<wt-assistant-drawer[\s\S]*?<\/wt-assistant-drawer>/)[0];

async function main() {
  const dom = new JSDOM(`<body>${drawer}<main id="content"><h1 class="page-title">Rulesets</h1><a data-ruleset-link aria-current="true"><span>Default Dev Ruleset</span></a>
    <button id="ask" data-assistant-open data-assistant-context="Help manage ruleset ID 7.">Ask</button></main></body>`,
    {url: 'https://watchtower.example/rulesets/7', runScripts: 'dangerously'});
  const w = dom.window;
  Object.defineProperty(w.navigator, 'clipboard', {value: {writeText: async value => { copied = value; }}, configurable: true});
  let copied = null;
  const requests = [];
  let loseReply = true;
  let actionsOn = false;
  let withChange = false;
  let changeSet = {id: 'cs-1', version: 3, status: 'DRAFT', contentHash: 'h', expiresAt: Date.now() + 30 * 60000, receipt: null,
    preview: {operations: [{type: 'INHERIT', target: '7'}], repositories: [{before: {id: 4, name: 'wt-test', ruleset: 'Default Dev Ruleset'}, after: {id: 4, name: 'wt-test', ruleset: 'Default Dev Ruleset'}}],
      rulesets: [{id: '7', before: {name: 'Default Dev Ruleset', inherited: ['A']}, after: {name: 'Default Dev Ruleset', inherited: ['A', 'AWS Security Agent · Security review']}, effectiveAdded: [99], effectiveRemoved: [], secretsCoverageRemoved: [], blockingReduced: false}]}};
  let readiness = {ready: false, problem: 'NO_API_KEY', message: 'No OpenAI API key is configured. An Assistant Admin can add it in Assistant settings → AI integration.'};
  w.fetch = async (url, options = {}) => {
    requests.push({url, options});
    if (url === '/assistant/status') return {ok: true, json: async () => readiness};
    if (url === '/assistant/models') return {ok: true, json: async () => ({models: [{id: 'tested', efforts: ['low', 'none']}, {id: 'other', efforts: ['high']}], defaultModel: 'tested', defaultEffort: 'low', retentionDays: 14, rulesetActions: actionsOn})};
    if (url === '/assistant/budget') return {ok: true, json: async () => ({usedCostMicros: 120000, dailyCostMicros: 2000000})};
    if (url.startsWith('/assistant/change-sets/cs-1')) {
      if (url.endsWith('/apply')) { changeSet = Object.assign({}, changeSet, {status: 'APPLIED', receipt: {appliedAt: Date.now(), actor: 'me'}}); }
      if (url.endsWith('/cancel')) { changeSet = Object.assign({}, changeSet, {status: 'CANCELED'}); }
      return {ok: true, json: async () => changeSet};
    }
    if (url.endsWith('/outcome')) return {ok: true, json: async () => ({status: 'saved'})};
    if (url === '/assistant/active') return {ok: true, json: async () => []};
    if (url === '/assistant/turn') {
      if (loseReply) {loseReply = false; throw new Error('Connection lost');}
      return {ok: true, json: async () => ({sessionId: 'session', turnId: 'turn'})};
    }
    return {ok: true, json: async () => ({status: 'COMPLETED', answer: '<img src=x onerror=alert(1)> [bad](javascript:alert) [rule](/rule/edit/regex/1)', activity: [{tool: 'get_rule', status: 'read'}], expiresAt: Date.now() + 86400000,
      citations: [{id: 11, name: 'private-key'}, {id: 'x"', name: 'bad id'}], changeSets: withChange ? ['cs-1'] : []})};
  };
  w.eval(fs.readFileSync(path.join(resources, 'static/scripts/assistant.js'), 'utf8'));
  const component = w.document.querySelector('wt-assistant-drawer');
  component.dataset.csrfHeader = 'X-CSRF-TOKEN';
  component.dataset.csrfToken = 'fixture';
  // Always present for Assistant Use: when chat cannot answer, the drawer says why and offers no chat controls.
  await component.open();
  const setup = component.querySelector('[data-assistant-setup]');
  assert.equal(setup.hidden, false);
  assert.equal(setup.querySelector('[data-assistant-setup-label]').textContent, 'Chat needs setup');
  assert.match(setup.getAttribute('data-tip'), /No OpenAI API key is configured/);
  assert.equal(component.form.hidden, true);
  assert.equal(component.panel.hidden, false, 'a side panel, not a modal');
  assert.equal(w.document.body.classList.contains('wt-assistant-open'), true, 'the page makes room for the panel');
  assert.equal(component.querySelector('.wt-assistant-toolbar').hidden, true);
  assert.equal(requests.some(r => r.url === '/assistant/models'), false, 'no chat request while not ready');
  readiness = {ready: false, problem: 'CHAT_OFF', message: 'An Assistant Admin can turn chat on in AI settings.'};
  await component.open();
  assert.equal(setup.querySelector('[data-assistant-setup-label]').textContent, 'Chat is off');
  assert.equal(component.querySelector('[data-assistant-intro]').hidden, false);
  assert.equal(component.querySelector('[data-assistant-settings]').hidden, false);
  component.input.value = 'Do not submit while chat is off';
  await component.submit();
  assert.equal(requests.some(r => r.url === '/assistant/turn'), false);
  readiness = {ready: true, problem: null, message: 'Chat is ready.'};
  await component.open();
  assert.equal(setup.hidden, true);
  assert.equal(component.form.hidden, false);
  assert.equal(component.model.value, 'tested');
  assert.equal(component.effort.value, 'low');
  assert.equal(component.querySelector('[data-assistant-model-label]').textContent, 'tested · low');
  assert.equal(component.querySelector('[data-assistant-readonly-chip]').hidden, false, 'read-only while Ruleset actions are off');
  assert.equal(component.querySelector('[data-assistant-actions-chip]').hidden, true);
  assert.equal(component.querySelector('[data-assistant-context-label]').textContent, 'Looking at: Default Dev Ruleset');
  assert.equal(component.querySelector('[data-assistant-start-title]').textContent, 'Ask about this ruleset');
  assert.equal(component.querySelectorAll('[data-assistant-starters] button').length, 2, 'no change starter while read-only');
  assert.equal(component.querySelector('[data-assistant-budget-label]').textContent, 'Today: $0.12 of $2');
  // Choosing a model in the chip menu keeps only that model's efforts.
  [...component.querySelectorAll('[data-assistant-model-menu] button')].find(b => b.textContent === 'other').click();
  assert.equal(component.model.value, 'other');
  assert.equal(component.effort.value, 'high');
  [...component.querySelectorAll('[data-assistant-model-menu] button')].find(b => b.textContent === 'tested').click();
  component.input.value = 'Explain this rule';
  await component.submit();
  const first = JSON.parse(requests.find(r => r.url === '/assistant/turn').options.body);
  assert.match(first.message, /^\[Looking at: Default Dev Ruleset · \/rulesets\/7\]\n\nExplain this rule$/, 'the page name goes with the message');
  await component.submit();
  await new Promise(resolve => setTimeout(resolve, 0));
  const submissions = requests.filter(r => r.url === '/assistant/turn');
  assert.equal(JSON.parse(submissions[1].options.body).idempotencyKey, first.idempotencyKey);
  assert.equal(submissions[1].options.headers['X-CSRF-TOKEN'], 'fixture');
  assert.equal(component.busy, false);
  assert.equal(component.messages.querySelector('img'), null);
  assert.equal(component.messages.querySelector('a').getAttribute('href'), '/rule/edit/regex/1');
  assert.equal(component.messages.querySelector('.wt-assistant-message--user').textContent, 'Explain this rule', 'the context prefix is not shown as typed text');
  assert.match(component.status.textContent, /get rule \(read\)/);
  const cited = [...component.messages.querySelectorAll('.wt-assistant-cited a')];
  assert.deepEqual(cited.map(a => [a.lastChild.textContent, a.getAttribute('href')]), [['private-key', '/rules/11/health']], 'only numeric rule ids become cited chips');
  component.messages.querySelector('[aria-label="Helpful"]').click();
  await new Promise(resolve => setTimeout(resolve, 0));
  const rating = requests.find(r => r.url === '/assistant/turn/turn/outcome');
  assert.equal(JSON.parse(rating.options.body).rating, 5);
  assert.equal(component.messages.querySelector('[aria-label="Helpful"]').getAttribute('aria-pressed'), 'true');
  component.messages.querySelector('[aria-label="Copy answer"]').click();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(copied, /\[rule\]\(\/rule\/edit\/regex\/1\)/);
  assert.match(component.messages.textContent, /javascript:alert/);
  assert.equal(component.querySelector('[data-assistant-start]').hidden, true, 'starters leave once the chat has messages');
  await component.poll();
  assert.equal(component.messages.querySelectorAll('section').length, 2);
  w.document.querySelector('#content').replaceChildren(w.document.createElement('p'));
  assert.equal(component.session, 'session');
  assert.equal(component.messages.querySelectorAll('section').length, 2);

  // Durable progress streams over SSE; terminal events close it and a closed stream falls back to polling.
  const streams = [];
  class FakeSource {
    constructor(url) {this.url = url; this.readyState = 0; this.listeners = {}; streams.push(this);}
    addEventListener(name, listener) {this.listeners[name] = listener;}
    emit(name, data) {this.listeners[name]({data: JSON.stringify(data)});}
    close() {this.readyState = FakeSource.CLOSED; this.closed = true;}
  }
  FakeSource.CLOSED = 2;
  w.EventSource = FakeSource;
  component.input.value = 'Stream this';
  await component.submit();
  assert.equal(streams.length, 1);
  assert.equal(streams[0].url, '/assistant/turn/turn/events');
  streams[0].emit('turn', {status: 'RUNNING', activity: [{tool: 'search_rules', status: 'read'}], expiresAt: Date.now() + 86400000});
  assert.match(component.status.textContent, /Working · search rules \(read\)/);
  assert.equal(component.busy, true);
  streams[0].emit('turn', {status: 'COMPLETED', answer: 'Streamed answer\n\n### How to measure\n- **Highest** false-alarm rate\n- Most `bypasses` <b>x</b>\n1. First\n2. Second', activity: {array: true, nodeType: 'ARRAY'}, expiresAt: Date.now() + 86400000});
  assert.equal(streams[0].closed, true);
  assert.equal(component.busy, false);
  assert.match(component.messages.textContent, /Streamed answer/);
  // Markdown reads as formatting, never as raw ** or - markers, and model HTML stays text (user, 2026-10-22).
  var last = [...component.messages.querySelectorAll('.wt-assistant-message--assistant')].at(-1);
  assert.equal(last.querySelectorAll('ul > li').length, 2);
  assert.equal(last.querySelectorAll('ol > li').length, 2);
  assert.equal(last.querySelector('ul strong').textContent, 'Highest');
  assert.equal(last.querySelector('ul code').textContent, 'bypasses');
  assert.equal(last.querySelector('.wt-assistant-heading').textContent, 'How to measure');
  assert.equal(last.querySelector('b'), null, 'model HTML is shown as text, not markup');
  assert.doesNotMatch(last.textContent, /\*\*|###/);
  const polled = () => requests.filter(r => r.url === '/assistant/turn/turn').length;
  component.input.value = 'Fallback';
  await component.submit();
  const before = polled();
  streams[1].readyState = FakeSource.CLOSED;
  streams[1].onerror();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(polled(), before + 1);
  assert.equal(component.busy, false);
  component.input.value = 'Revoked';
  await component.submit();
  streams[2].emit('end', {status: 'closed'});
  assert.equal(streams[2].closed, true);
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(polled(), before + 2);

  // Removing the context chip stops sending the page name; New chat brings the starters back.
  component.querySelector('[data-assistant-context-remove]').click();
  assert.equal(component.querySelector('[data-assistant-context-chip]').hidden, true);
  component.querySelector('[data-assistant-new]').click();
  assert.equal(component.messages.children.length, 0);
  assert.equal(component.querySelector('[data-assistant-start]').hidden, false);
  assert.equal(component.querySelector('[data-assistant-start-title]').textContent, 'Ask about rules and findings');
  delete w.EventSource;
  component.input.value = 'Plain question';
  await component.submit();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(JSON.parse(requests.filter(r => r.url === '/assistant/turn').at(-1).options.body).message, 'Plain question');

  // A page button re-shares the page; with Ruleset actions on, a prepared change set becomes an approval card.
  actionsOn = true; component.models = null; withChange = true;
  w.document.querySelector('#content').innerHTML = '<button id="ask" data-assistant-open data-assistant-subject="Default Dev Ruleset" data-assistant-context="Help manage ruleset ID 7.">Ask</button>';
  await component.open(null, w.document.getElementById('ask'));
  assert.equal(component.querySelector('[data-assistant-actions-chip]').hidden, false);
  assert.equal(component.querySelector('[data-assistant-context-chip]').hidden, false);
  component.querySelector('[data-assistant-new]').click();
  assert.equal(component.querySelectorAll('[data-assistant-starters] button').length, 3, 'change starter only with Ruleset actions on');
  component.input.value = 'Add the AWS review';
  await component.submit();
  for (let i = 0; i < 5; i++) await new Promise(resolve => setTimeout(resolve, 0));
  assert.match(JSON.parse(requests.filter(r => r.url === '/assistant/turn').at(-1).options.body).message, /Help manage ruleset ID 7\./);
  const card = component.messages.querySelector('[data-change-set="cs-1"]');
  assert.ok(card, 'change set card shown');
  assert.match(card.textContent, /Change what "Default Dev Ruleset" includes/);
  assert.match(card.textContent, /\+1 rule/);
  assert.match(card.textContent, /No rules removed/);
  assert.match(card.textContent, /Includes AWS Security Agent · Security review/);
  assert.match(card.textContent, /Affects 1 repository: wt-test/);
  assert.match(card.textContent, /Preview checked[\s\S]*Expires in 30 min[\s\S]*Needs your approval/);
  assert.equal(requests.some(r => r.url.endsWith('/apply')), false, 'nothing is applied without approval');
  [...card.querySelectorAll('md-filled-button')].find(b => /Approve and apply/.test(b.textContent)).click();
  for (let i = 0; i < 3; i++) await new Promise(resolve => setTimeout(resolve, 0));
  const apply = requests.find(r => r.url === '/assistant/change-sets/cs-1/apply');
  assert.deepEqual(JSON.parse(apply.options.body), {version: 3, contentHash: 'h', deletionNames: {}});
  assert.equal(apply.options.headers['X-CSRF-TOKEN'], 'fixture');
  assert.match(card.textContent, /Applied .* · receipt #cs-1/);
  assert.equal(card.querySelector('md-filled-button'), null);
  // A deletion needs the typed name on the full review page, never an inline approve.
  changeSet = Object.assign({}, changeSet, {status: 'DRAFT', preview: Object.assign({}, changeSet.preview, {operations: [{type: 'DELETE', target: '7'}]})});
  const host = w.document.createElement('section');
  await component.changeCard(host, 'cs-1');
  const del = host.querySelector('md-filled-button');
  assert.equal(del.textContent, 'Review and delete');
  assert.equal(del.getAttribute('href'), '/assistant/change-sets/cs-1/review');
  component.querySelector('[data-assistant-close]').click();
  assert.equal(component.panel.hidden, true);
  assert.equal(w.document.body.classList.contains('wt-assistant-open'), false);
  // An ended session answers with the sign-in page; the drawer says so instead of a JSON parse error.
  const realFetch = w.fetch;
  w.fetch = async () => ({ok: true, url: 'https://watchtower.example/login', headers: {get: () => 'text/html;charset=UTF-8'}, json: async () => { throw new SyntaxError('Unexpected token <'); }});
  await assert.rejects(() => component.api('/assistant/status'), error => /session has ended/.test(error.message) && error.status === 401);
  w.fetch = realFetch;
  dom.window.close();
  console.log('Assistant panel, context, citations, change-set, retry, rendering, navigation and streaming tests passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});

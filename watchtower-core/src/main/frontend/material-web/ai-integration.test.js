const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
const page = fs.readFileSync(path.join(resources, 'templates/assistant/admin.html'), 'utf8');
const dialogMarkup = page.match(/<md-dialog data-ai-integration-dialog[\s\S]*?<\/md-dialog>/)[0];
const KEY = 'sk-proj-synthetic0000000000000000000000';

async function main() {
  const dom = new JSDOM(`<body><div data-assistant-admin data-csrf-header="X-CSRF-TOKEN" data-csrf-token="fixture">
    <md-outlined-button data-ai-integration-open>AI integration</md-outlined-button>${dialogMarkup}</div></body>`,
    {url: 'https://watchtower.example/admin/assistant', runScripts: 'dangerously'});
  const w = dom.window;
  const dialog = w.document.querySelector('[data-ai-integration-dialog]');
  dialog.show = async () => { dialog.open = true; };
  dialog.close = () => { dialog.open = false; };
  const requests = [];
  let view = {provider: 'OPENAI', name: 'OpenAI', configured: false, version: 0, encrypted: false};
  const configured = () => ({...view, configured: true, updatedBy: 'admin <b>x</b>', updatedAt: Date.UTC(2026, 9, 13), version: 1, encrypted: true});
  let confirmAnswer = false;
  w.confirm = () => confirmAnswer;
  w.fetch = async (url, options = {}) => {
    requests.push({url, options});
    const reply = (body, ok = true, status = 200) => ({ok, status, json: async () => body});
    const base = '/admin/assistant/integrations/openai';
    if (url === base && !options.method) return reply(view);
    if (url === base && JSON.parse(options.body).apiKey === 'bad') return reply({error: 'Enter an OpenAI API key; it starts with sk-.'}, false, 400);
    if (url === base) { view = configured(); return reply(view); }
    if (url === base + '/test') { view = {...view, healthCheckedAt: Date.UTC(2026, 9, 13), healthOk: false, healthError: 'PROVIDER_AUTHENTICATION'}; return reply({ok: false, message: 'OpenAI rejected the key.', integration: view}); }
    if (url === base + '/remove') { view = {...view, configured: false, version: 2}; return reply(view); }
    return reply({}, false, 404);
  };
  w.eval(fs.readFileSync(path.join(resources, 'static/scripts/ai-integration.js'), 'utf8'));
  const settle = async () => { for (let i = 0; i < 4; i++) await new Promise(resolve => setTimeout(resolve, 0)); };
  const q = name => dialog.querySelector('[data-ai-integration-' + name + ']');

  const chipText = () => Array.from(q('state').querySelectorAll('.wt-mini-chip')).map(c => c.textContent.trim());
  const tipOf = label => Array.from(q('state').querySelectorAll('.wt-mini-chip')).find(c => c.textContent.includes(label)).dataset.tip;
  w.document.querySelector('[data-ai-integration-open]').click(); await settle();
  assert.equal(dialog.open, true);
  assert.deepEqual(chipText(), ['key_offNo key', 'no_encryptionStored unencrypted'], 'no key yet, and an unencrypted database is stated, not hidden');
  assert.doesNotMatch(dialog.textContent, /watchtower\.encryption/, 'the internal setting name is not shown');
  assert.match(q('key').supportingText, /stored unencrypted/, 'the key field never claims encryption that is off');
  assert.equal(q('key').hidden, false, 'with no key the field is open');
  assert.equal(q('remove').hidden, true, 'nothing to remove yet');
  assert.equal(q('test').hidden, true, 'nothing to test yet');
  assert.equal(q('replace').hidden, true);

  q('save').click(); await settle();
  assert.match(q('status').textContent, /Enter the API key/);
  assert.equal(requests.filter(r => r.options.method).length, 0, 'a blank key is not sent');

  q('key').value = 'bad'; q('save').click(); await settle();
  assert.match(q('status').textContent, /starts with sk-/);
  assert.equal(q('key').value, '', 'a rejected key is cleared from the field');

  q('key').value = '  ' + KEY + ' '; q('save').click(); await settle();
  const saved = requests.filter(r => r.options.method).pop();
  assert.deepEqual(JSON.parse(saved.options.body), {apiKey: KEY, version: 0});
  assert.equal(saved.options.headers['X-CSRF-TOKEN'], 'fixture');
  assert.equal(q('key').value, '', 'the key is not kept in the page after saving');
  assert.deepEqual(chipText(), ['keyKey saved', 'network_checkNot tested', 'lockStored encrypted']);
  assert.match(tipOf('Key saved'), /Saved by admin <b>x<\/b> on .*never shown again/);
  assert.equal(dialog.querySelector('b'), null, 'server text is rendered as text');
  assert.equal(q('key').supportingText, 'Stored encrypted and never shown again');
  assert.equal(q('key').hidden, true, 'a saved key is replaced on request, not by an always-open field');
  assert.equal(q('save').hidden, true);
  assert.equal(q('replace').hidden, false);
  assert.equal(q('remove').hidden, false);
  assert.equal(q('test').hidden, false);
  q('replace').click(); await settle();
  assert.equal(q('key').hidden, false, 'Replace key opens the field');
  assert.equal(q('save').hidden, false);
  assert.equal(q('replace').hidden, true);
  assert.match(q('key').label, /replaces the saved one/);

  q('test').click(); await settle();
  assert.match(q('status').textContent, /rejected the key/);
  assert.ok(chipText().includes('errorTest failing'));
  assert.match(tipOf('Test failing'), /^OpenAI rejected the key since /, 'the failure reads in plain words');
  assert.doesNotMatch(q('state').textContent, /PROVIDER_AUTHENTICATION/, 'no internal codes');

  q('remove').click(); await settle();
  assert.equal(requests.filter(r => r.url.endsWith('/remove')).length, 0, 'removal waits for confirmation');
  confirmAnswer = true; q('remove').click(); await settle();
  const removed = requests.find(r => r.url.endsWith('/remove'));
  assert.deepEqual(JSON.parse(removed.options.body), {version: 1});
  assert.ok(chipText().includes('key_offNo key'));
  assert.ok(requests.every(r => !(r.options.body || '').includes(KEY) || r === saved), 'the key is only ever sent once, when saved');

  q('close').click();
  assert.equal(dialog.open, false);
  w.close();
  console.log('AI integration: state chips, write-only key, Replace key, CSRF save, plain-word test result, confirmed removal and safe rendering passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});

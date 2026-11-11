const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
const template = fs.readFileSync(path.join(resources, 'templates/fragments/container.html'), 'utf8');
const drawer = template.match(/<wt-assistant-drawer[\s\S]*?<\/wt-assistant-drawer>/)[0];

const ok = body => ({ok: true, json: async () => body});

async function main() {
  const dom = new JSDOM(`<body>${drawer}<main><h1 class="page-title">Home</h1></main></body>`,
    {url: 'https://watchtower.example/', runScripts: 'dangerously'});
  const w = dom.window;
  const requests = [];
  let chats = [
    {session_id: 's-1', started_at: Date.UTC(2026, 9, 24, 14, 35), model: 'tested', title: 'Why is this rule noisy?'},
    {session_id: 's-2', started_at: Date.UTC(2026, 9, 19, 16, 17), model: 'tested', title: null}
  ];
  let releaseReopen;
  const reopenGate = new Promise(resolve => { releaseReopen = resolve; });
  w.fetch = async (url, options = {}) => {
    const method = options.method || 'GET';
    requests.push({url, method, headers: options.headers || {}});
    if (url === '/assistant/status') return ok({ready: true, problem: null, message: 'Chat is ready.'});
    if (url === '/assistant/models') return ok({models: [{id: 'tested', efforts: ['low']}], defaultModel: 'tested', defaultEffort: 'low', retentionDays: 14});
    if (url === '/assistant/budget') return ok({usedCostMicros: 0, dailyCostMicros: 2000000});
    if (url === '/assistant/active') return ok([]);
    if (url.startsWith('/assistant/history?')) return ok(chats);
    if (method === 'DELETE' && url.startsWith('/assistant/history/')) {
      const id = decodeURIComponent(url.slice('/assistant/history/'.length));
      chats = chats.filter(chat => chat.session_id !== id);
      return ok({status: 'DELETED'});
    }
    if (url === '/assistant/history/s-1') {
      await reopenGate;
      return ok({session: {model: 'tested', effort: 'low', expires_at: Date.now() + 86400000}, messages: [{role: 'user', text: 'Why is this rule noisy?'}], turns: []});
    }
    return ok({});
  };
  w.eval(fs.readFileSync(path.join(resources, 'static/scripts/assistant.js'), 'utf8'));
  const component = w.document.querySelector('wt-assistant-drawer');
  component.dataset.csrfHeader = 'X-CSRF-TOKEN';
  component.dataset.csrfToken = 'fixture';
  await component.open();
  const list = () => component.querySelector('[data-assistant-history-list]');
  const rows = () => Array.from(list().querySelectorAll('.wt-assistant-history-row'));
  const deletes = () => requests.filter(r => r.method === 'DELETE');

  // A titled chat is listed under its title; an older chat without one keeps the date and model.
  await component.history();
  assert.equal(rows().length, 2);
  const [titled, untitled] = rows();
  assert.equal(titled.querySelector('.wt-menu-item').textContent, 'Why is this rule noisy?');
  assert.match(titled.querySelector('.wt-menu-item').title, /tested/, 'hover still shows the model');
  assert.match(untitled.querySelector('.wt-menu-item').textContent, / · tested$/);
  rows().forEach(row => assert.equal(row.querySelector('.wt-icon-action').getAttribute('aria-label'), 'Delete this chat'));

  // The trash button asks first; Keep puts the row back and deletes nothing.
  untitled.querySelector('.wt-icon-action').click();
  assert.match(rows()[1].textContent, /Delete this chat\?/);
  assert.deepEqual(Array.from(rows()[1].querySelectorAll('button')).map(b => b.textContent), ['Delete', 'Keep']);
  assert.equal(deletes().length, 0, 'nothing is deleted before the person confirms');
  Array.from(rows()[1].querySelectorAll('button')).find(b => b.textContent === 'Keep').click();
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(rows().length, 2);
  assert.equal(deletes().length, 0);

  // Confirming sends one DELETE with the CSRF header and refreshes the list.
  rows()[1].querySelector('.wt-icon-action').click();
  Array.from(rows()[1].querySelectorAll('button')).find(b => b.textContent === 'Delete').click();
  await new Promise(resolve => setTimeout(resolve, 0));
  await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(deletes().length, 1);
  assert.equal(deletes()[0].url, '/assistant/history/s-2');
  assert.equal(deletes()[0].headers['X-CSRF-TOKEN'], 'fixture');
  assert.equal(rows().length, 1);
  assert.equal(component.status.textContent, 'Chat deleted.');

  // Deleting the chat that is open starts a new one.
  let startedNew = false;
  component.newChat = () => { startedNew = true; };
  component.session = 's-1';
  await component.removeChat('s-1');
  assert.equal(startedNew, true);
  assert.equal(list().textContent.includes('No earlier chats.'), true);

  // Opening a chat says it is loading until the transcript arrives.
  const opening = component.reopen('s-1');
  assert.equal(component.status.textContent, 'Loading chat…');
  releaseReopen();
  await opening;
  assert.equal(component.status.textContent, '');
  dom.window.close();
  console.log('Assistant earlier-chat titles, delete confirm and loading tests passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});

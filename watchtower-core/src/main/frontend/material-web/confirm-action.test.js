const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/confirm-action.js'), 'utf8');

function load(body) {
  const dom = new JSDOM(`<!doctype html><body>${body}</body>`, {runScripts: 'dangerously'});
  const {window} = dom;
  // md-dialog stand-in: show/close and the "closed" event, as Material Web provides.
  window.HTMLElement.prototype.show = function () { this.open = true; };
  window.HTMLElement.prototype.close = function () {
    this.open = false;
    this.dispatchEvent(new window.Event('closed'));
  };
  window.eval(script);
  return window;
}

const page = `
  <form id="danger" method="post" action="/apisettings/delete"
      data-confirm="Delete integration bitbucket? Scans using it stop connecting."
      data-confirm-action="Delete integration">
    <button id="submit" type="submit">Delete</button>
  </form>
  <form id="plain" method="post" action="/elsewhere"><button id="plainSubmit">Go</button></form>`;

{
  const window = load(page);
  const document = window.document;
  const form = document.getElementById('danger');
  let submitted = 0;
  // Stands in for htmx's boosted-form listener: must only see a confirmed submit.
  form.addEventListener('submit', (event) => { event.preventDefault(); submitted++; });

  document.getElementById('submit').click();
  const dialog = document.querySelector('[data-confirm-dialog]');
  assert.ok(dialog, 'submitting a form that needs confirmation opens the dialog');
  assert.equal(dialog.open, true);
  assert.equal(submitted, 0, 'nothing is submitted before the user confirms');
  assert.equal(dialog.querySelector('[data-confirm-message]').textContent,
    'Delete integration bitbucket? Scans using it stop connecting.');
  assert.equal(dialog.querySelector('[data-confirm-ok]').textContent, 'Delete integration');

  assert.match(dialog.querySelector('[data-confirm-headline]').textContent, /^delete_forever\s*Delete integration\?$/,
    'a delete asks with the delete tile and its own title');

  dialog.querySelector('[data-confirm-cancel]').click();
  assert.equal(dialog.open, false, 'cancel closes the dialog');
  assert.equal(submitted, 0, 'cancel submits nothing');

  document.getElementById('submit').click();
  dialog.querySelector('[data-confirm-ok]').click();
  assert.equal(submitted, 1, 'confirming submits the original form once');
  assert.equal(dialog.open, false);

  document.getElementById('submit').click();
  assert.equal(submitted, 1, 'the next submit asks again');
}

{
  const window = load(`<form id="t" data-confirm="Sure?" data-confirm-action="Delete" data-confirm-title="Delete repository?">
    <button id="ts" type="submit">x</button></form>
    <form id="o" data-confirm="Pause?" data-confirm-action="Pause"><button id="os" type="submit">x</button></form>`);
  window.document.getElementById('t').addEventListener('submit', (e) => e.preventDefault());
  window.document.getElementById('o').addEventListener('submit', (e) => e.preventDefault());
  window.document.getElementById('ts').click();
  const headline = window.document.querySelector('[data-confirm-headline]');
  assert.match(headline.textContent, /Delete repository\?$/, 'a form can name its own delete title');
  window.document.querySelector('[data-confirm-cancel]').click();
  window.document.getElementById('os').click();
  assert.equal(headline.textContent, 'Are you sure?', 'other confirmations keep the plain question');
}

{
  // Messages are text, never markup.
  const window = load(`<form id="f" data-confirm="<img src=x onerror=alert(1)>">
    <button id="s" type="submit">x</button></form>`);
  window.document.getElementById('f').addEventListener('submit', (e) => e.preventDefault());
  window.document.getElementById('s').click();
  const message = window.document.querySelector('[data-confirm-message]');
  assert.equal(message.querySelector('img'), null);
}

{
  const window = load(page);
  const plain = window.document.getElementById('plain');
  let submitted = 0;
  plain.addEventListener('submit', (event) => { event.preventDefault(); submitted++; });
  window.document.getElementById('plainSubmit').click();
  assert.equal(submitted, 1, 'forms without data-confirm submit as before');
  assert.equal(window.document.querySelector('[data-confirm-dialog]'), null);
}

console.log('confirm-action tests passed');

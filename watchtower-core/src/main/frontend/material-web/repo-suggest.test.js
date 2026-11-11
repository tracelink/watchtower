const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/repo-suggest.js'), 'utf8');
const dom = new JSDOM(`<!doctype html><body><form>
  <select name="apiLabel"><option value="BitBucket" selected>BitBucket</option></select>
  <input name="repo" data-repo-suggest="repo-suggestions">
  <div id="repo-suggestions" role="listbox" hidden></div>
</form></body>`, {runScripts: 'dangerously'});
const calls = [];
dom.window.fetch = async url => {
  calls.push(url);
  return {ok: true, json: async () => [{name: 'wt-test', project: 'WPRT', status: 'Active'},
    {name: '<img src=x onerror=alert(1)>', project: null, status: 'Paused'}]};
};
dom.window.eval(script);

(async () => {
  const document = dom.window.document;
  const field = document.querySelector('[name="repo"]');
  const list = document.getElementById('repo-suggestions');
  field.value = 'wt-';
  field.dispatchEvent(new dom.window.Event('input'));
  await new Promise(resolve => setTimeout(resolve, 260));
  assert.equal(calls.length, 1);
  assert.equal(calls[0], '/scan/repositories?apiLabel=BitBucket&q=wt-');
  assert.equal(list.hidden, false);
  const options = list.querySelectorAll('[role="option"]');
  assert.equal(options.length, 2);
  assert.equal(options[0].querySelector('strong').textContent, 'wt-test');
  assert.equal(options[0].querySelector('.wt-combo__meta').textContent, 'WPRT · Active');
  assert.equal(list.querySelector('img'), null, 'suggestions are text, never markup');
  options[0].click();
  assert.equal(field.value, 'wt-test');
  assert.equal(list.hidden, true);
  console.log('Repository suggestions jsdom test passed');
})().catch(error => { console.error(error); process.exit(1); });

// A page can name its own list (the secrets allowlist: every integration, no integration field);
// only a same-origin path is accepted.
(async () => {
  const own = new JSDOM(`<!doctype html><body><form>
    <input name="repoName" data-repo-suggest="allowlist-suggestions" data-repo-suggest-url="/betterleaks/allowlist/repositories">
    <div id="allowlist-suggestions" role="listbox" hidden></div>
  </form></body>`, {runScripts: 'dangerously'});
  const urls = [];
  own.window.fetch = async url => { urls.push(url); return {ok: true, json: async () => []}; };
  own.window.eval(script);
  const field = own.window.document.querySelector('[name="repoName"]');
  field.value = 'pay';
  field.dispatchEvent(new own.window.Event('input'));
  await new Promise(resolve => setTimeout(resolve, 260));
  assert.deepEqual(urls, ['/betterleaks/allowlist/repositories?q=pay']);

  const offsite = new JSDOM(`<!doctype html><body><form>
    <input name="repoName" data-repo-suggest="s" data-repo-suggest-url="https://evil.example/x">
    <div id="s" role="listbox" hidden></div></form></body>`, {runScripts: 'dangerously'});
  const offsiteUrls = [];
  offsite.window.fetch = async url => { offsiteUrls.push(url); return {ok: true, json: async () => []}; };
  offsite.window.eval(script);
  const offField = offsite.window.document.querySelector('[name="repoName"]');
  offField.dispatchEvent(new offsite.window.Event('input'));
  await new Promise(resolve => setTimeout(resolve, 260));
  assert.deepEqual(offsiteUrls, [], 'an off-site list is ignored');
  console.log('Repository suggestions: a page-named same-origin list is used');
})().catch(error => { console.error(error); process.exit(1); });

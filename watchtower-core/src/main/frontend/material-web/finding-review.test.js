const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
const tick = () => new Promise(resolve => setTimeout(resolve, 0));
async function main() {
  const template = fs.readFileSync(path.join(resources, 'templates/feedback/review.html'), 'utf8');
  const dom = new JSDOM('<body>' + template + '</body>', {url: 'https://watchtower.example/finding-feedback/review', runScripts: 'dangerously'});
  const w = dom.window, root = w.document.querySelector('[data-feedback-page]');
  Object.assign(root.dataset, {scanType: 'pull_request', scanId: '1', findingKey: '7', version: '2', csrfHeader: 'X-CSRF-TOKEN', csrfToken: 'fixture'});
  let requests = [], saves = [], reject = false;
  w.fetch = async (url, options = {}) => {
    requests.push(url);
    if (options.method) {
      assert.equal(options.headers['X-CSRF-TOKEN'], 'fixture'); saves.push(JSON.parse(options.body));
      return {ok: !reject, status: reject ? 409 : 200, json: async () => ({status: 'saved'})};
    }
    const history = url.includes('/history?');
    return {ok: true, json: async () => ({content: history ? [{judgment: 'TRUE_POSITIVE', disposition: 'ACCEPTED_RISK', explanation: '<img src=x>', reviewer: 'Reviewer', changedAt: 1700000000000}]
      : [{key: '8', version: 0, title: '<img src=x>', severity: 'High', file: 'src/App.java', line: 42}], totalElements: 1, totalPages: 1})};
  };
  const script = fs.readFileSync(path.join(resources, 'static/scripts/finding-review.js'), 'utf8');
  w.eval(script); w.eval(script);
  assert.equal(requests.length, 0, 'No work is requested until an explicit action');
  assert.equal(root.querySelector('[data-review-selected-count]').textContent, '1 occurrence selected');
  // Correctness and handling are radio choices (large cards and icon chips).
  root.querySelector('[data-review-judgment] input[value="TRUE_POSITIVE"]').checked = true;
  root.querySelector('[data-review-disposition] input[value="ACCEPTED_RISK"]').checked = true;
  root.querySelector('[data-review-explanation]').value = 'Accepted risk remains a correct detection.';
  const submit = () => root.querySelector('[data-review-form]').dispatchEvent(new w.Event('submit', {bubbles: true, cancelable: true}));
  submit(); submit(); await tick();
  assert.equal(saves.length, 1, 'Repeated initialization and double submission do not duplicate saves');
  assert.deepEqual(saves[0].findingKeys, ['7']); assert.equal(saves[0].versions['7'], 2);
  assert.equal(saves[0].judgment, 'TRUE_POSITIVE'); assert.equal(saves[0].disposition, 'ACCEPTED_RISK');
  const bulk = root.querySelector('[data-review-bulk]'); bulk.open = true; await tick(); await tick();
  assert.equal(root.querySelector('[data-review-options] img'), null);
  assert.ok(root.querySelector('[data-review-options]').textContent.includes('src/App.java:42'));
  const choice = root.querySelector('[data-review-options] input'); choice.checked = true; choice.dispatchEvent(new w.Event('change'));
  assert.equal(root.querySelector('[data-review-selected-count]').textContent, '2 occurrences selected');
  reject = true; submit(); await tick();
  assert.deepEqual(saves[1].findingKeys, ['7', '8']); assert.equal(saves[1].versions['7'], 3);
  assert.equal(root.querySelector('[data-review-explanation]').value, 'Accepted risk remains a correct detection.');
  assert.match(root.querySelector('[data-review-status]').textContent, /Another reviewer/);
  assert.ok(!requests.some(url => url.includes('/history?')), 'History loads only when opened');
  const historySection = root.querySelector('[data-review-history-section]'); historySection.open = true; await tick(); await tick();
  assert.equal(root.querySelector('[data-review-history] img'), null);
  assert.match(root.querySelector('[data-review-history]').textContent, /<img src=x>/);
  assert.equal(root.querySelector('[data-review-history-next]').disabled, true);
  assert.ok(!requests.some(url => url.includes('assessment') || url.includes('assistant')));
  dom.window.close();
  console.log('Finding review: occurrence context, explicit bulk selection, single save, CSRF, conflict input preservation and safe paged history passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});

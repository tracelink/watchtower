const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
async function main() {
  const dom = new JSDOM(`<body><div data-feedback-context data-scan-type="pull_request" data-scan-id="1"></div>
    <section data-finding-workspace><input data-finding-search value="authentication"><select data-finding-severity><option value="1" selected>High</option></select><select data-finding-location><option value="">All</option></select>
    <div data-finding-item class="is-selected" data-feedback-key="7" data-title="First occurrence"></div>
    <a data-feedback-open>Review finding</a></section></body>`,
    {url: 'https://watchtower.example/scan/report/1?tab=findings', runScripts: 'dangerously'});
  const w = dom.window;
  w.fetch = () => {throw new Error('Opening a review link must not request AI or mutate feedback');};
  const navigation = fs.readFileSync(path.join(resources, 'static/scripts/finding-feedback.js'), 'utf8');
  w.eval(navigation); w.eval(navigation);
  const link = w.document.querySelector('[data-feedback-open]');
  const target = new URL(link.href);
  assert.equal(target.pathname, '/finding-feedback/review');
  assert.equal(target.searchParams.get('findingKey'), '7');
  const back = new URL(target.searchParams.get('returnTo'), w.location.origin);
  assert.equal(back.pathname, '/scan/report/1');
  assert.equal(back.searchParams.get('reviewFinding'), '7');
  assert.equal(back.searchParams.get('reviewSearch'), 'authentication');
  assert.equal(back.searchParams.get('reviewSeverity'), '1');
  w.document.querySelector('[data-finding-item]').classList.remove('is-selected');
  w.document.dispatchEvent(new w.Event('wt:finding-cleared'));
  assert.equal(link.hasAttribute('href'), false);
  assert.equal(link.getAttribute('aria-disabled'), 'true');
  w.document.querySelector('[data-finding-item]').classList.add('is-selected');
  w.document.dispatchEvent(new w.Event('wt:finding-selection'));
  w.HTMLElement.prototype.show = function () { this.open = true; };
  w.HTMLElement.prototype.close = function () { this.open = false; };
  w.fetch = async () => ({ok: true, text: async () => '<section data-feedback-page><form data-review-form>Review choices</form></section>'});
  link.click(); await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(w.location.pathname, '/scan/report/1');
  assert.ok(w.document.querySelector('md-dialog.wt-feedback-dialog [data-feedback-page]'));
  w.document.dispatchEvent(new w.CustomEvent('wt:review-saved', {detail: {
    scanType: 'pull_request', scanId: '1', findingKeys: ['7'], judgment: 'TRUE_POSITIVE'
  }}));
  assert.equal(w.document.querySelector('[data-finding-item]').dataset.reviewState, 'true');
  dom.window.close();
  const intakeFragment = fs.readFileSync(path.join(resources, 'templates/fragments/missedcase.html'), 'utf8');
  const intakeDom = new JSDOM(`<body><button data-missed-open>Record miss</button>${intakeFragment}</body>`, {url: 'https://watchtower.example/', runScripts: 'dangerously'});
  const iw = intakeDom.window, intakeDialog = iw.document.querySelector('[data-missed-dialog]');
  Object.assign(intakeDialog.dataset, {repoId: '42', csrfHeader: 'X-CSRF-TOKEN', csrfToken: 'fixture'});
  intakeDialog.show = async () => {}; intakeDialog.close = () => {};
  const values = {commit: 'a'.repeat(40), fixedCommit: '', affectedPath: 'app/source.py', firstLine: '3', evidenceType: 'PENTEST', evidenceRef: 'pentest/report-42', cwe: 'CWE-79', fixtureRef: 'fixtures/positive-v1.py', fixtureHash: 'b'.repeat(64), language: 'python', framework: 'unknown', frameworkVersion: 'unknown'};
  intakeDialog.querySelectorAll('[data-missed-field]').forEach(field => field.value = values[field.dataset.missedField]);
  // Evidence is a row of choice buttons now (radios), not a select.
  intakeDialog.querySelector('[data-missed-field="evidenceType"] input[value="PENTEST"]').checked = true;
  let caseSaved;
  iw.fetch = async (url, options = {}) => {
    if (options.method) { caseSaved = JSON.parse(options.body); assert.equal(options.headers['X-CSRF-TOKEN'], 'fixture'); }
    return {ok: true, json: async () => options.method ? {id: 'reviewed-case'} : [{evidence_type: 'PENTEST', cwe: 'CWE-79', affected_path: '<img src=x>', first_line: 3, commit_hash: values.commit, fixture_ref: values.fixtureRef, reviewer: 'alice'}]};
  };
  iw.eval(fs.readFileSync(path.join(resources, 'static/scripts/missed-case.js'), 'utf8'));
  iw.document.querySelector('[data-missed-open]').click(); await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(intakeDialog.querySelector('img'), null);
  assert.ok(intakeDialog.querySelector('[data-missed-list]').textContent.includes('<img src=x>'));
  assert.ok(intakeDialog.querySelector('[data-missed-list]').textContent.includes('Pentest · CWE-79'), 'evidence reads in plain words');
  intakeDialog.querySelector('[data-missed-save]').click(); await new Promise(resolve => setTimeout(resolve, 0));
  assert.equal(caseSaved.repositoryId, 42); assert.equal(caseSaved.evidenceType, 'PENTEST'); assert.equal(caseSaved.fixtureHash, 'b'.repeat(64)); assert.equal(caseSaved.fixedCommit, null); assert.equal(caseSaved.ruleId, null); assert.equal(caseSaved.firstLine, 3);
  assert.ok(intakeDialog.querySelector('[data-missed-status]').textContent.includes('Confirmed case saved'));
  intakeDom.window.close();
  console.log('Individual finding selection, independent judgment and reviewed missed-case intake tests passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});

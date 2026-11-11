const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const workspaceScript = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/finding-workspace.js'), 'utf8');
const sourceScript = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/scan-report-code.js'), 'utf8');

function findingMarkup(index, overrides = {}) {
  const severity = overrides.severity || (index % 2 ? '3' : '1');
  const title = overrides.title || `Finding ${index}`;
  const file = overrides.file || `src/File${index}.java`;
  const line = overrides.line || index;
  const guidance = overrides.guidance || `Guidance ${index}`;
  const sourceAction = overrides.sourceAction === undefined ? true : overrides.sourceAction;
  const url = overrides.url ? ` data-url="${overrides.url}"` : '';
  const selected = index === 1 ? ' class="is-selected" aria-pressed="true"' : ' aria-pressed="false"';
  return `<button data-finding-item${selected} data-severity="${severity}"
      data-feedback-key="${index}" data-location="${file}" data-location-label="${file}:${line}" data-title="${title}"
      data-guidance="${guidance}" data-file="${file}" data-line="${line}"
      data-source-action="${sourceAction}"${url}>
      <span class="wt-sev wt-sev-${severity}">${severity === '1' ? 'High' : 'Medium'}</span>
    </button>`;
}

function workspaceMarkup(id = 'workspace', findingCount = 2) {
  const findings = findingCount === 2
    ? `${findingMarkup(1, {title: 'Alpha', file: 'src/A.java', line: 4,
         guidance: 'First guidance'})}
       ${findingMarkup(2, {title: 'Beta', file: 'src/B.java', line: 9,
         guidance: 'Second guidance', sourceAction: false,
         url: 'https://example.invalid/beta'})}`
    : Array.from({length: findingCount}, (_, index) => findingMarkup(index + 1)).join('');
  return `<section id="${id}" data-finding-workspace>
    <input data-finding-search>
    <select data-finding-severity><option value="">All</option><option value="1">High</option></select>
    <select data-finding-location><option value="">All</option></select>
    <span data-finding-status></span><div data-finding-empty hidden></div>
    <div data-finding-list-viewport>${findings}</div>
    <nav data-finding-pagination aria-label="Findings pages">
      <span data-finding-range></span>
      <button type="button" data-finding-previous>Previous</button>
      <button type="button" data-finding-next>Next</button>
    </nav>
    <aside class="wt-finding-detail">
      <div class="wt-finding-detail-heading"><span class="wt-sev"></span></div>
      <h3 data-detail-title></h3><button data-copy-finding="title"></button>
      <span data-detail-location></span><button data-copy-finding="location"></button><p data-detail-guidance></p>
      <div data-detail-cvss><span data-detail-score></span></div>
      <div data-detail-vector-row><span data-detail-vector></span><button data-copy-finding="vector"></button></div>
      <span data-copy-status></span>
      <a data-detail-url></a><a class="wt-loc" href="#wt-code-section" data-detail-source></a>
    </aside>
  </section>`;
}

const dom = new JSDOM(`<!doctype html><body>${workspaceMarkup()}
  <section id="wt-code-section">
    <details data-file="src/A.java"><div class="wt-code-line" data-line="4"></div></details>
  </section></body>`, {runScripts: 'dangerously'});
dom.window.matchMedia = () => ({matches: true});
dom.window.HTMLElement.prototype.scrollIntoView = function () {};
let copiedValue = '';
Object.defineProperty(dom.window.navigator, 'clipboard', {value: {
  writeText: async value => { copiedValue = value; }
}});
dom.window.eval(workspaceScript);
dom.window.eval(sourceScript);

const document = dom.window.document;
const workspace = document.querySelector('[data-finding-workspace]');
const items = workspace.querySelectorAll('[data-finding-item]');
assert.equal(workspace.dataset.initialized, 'true');
assert.equal(workspace.querySelectorAll('[data-finding-location] option').length, 3);

workspace.querySelector('[data-finding-search]').value = 'second';
workspace.querySelector('[data-finding-search]').dispatchEvent(new dom.window.Event('input'));
assert.equal(items[0].hidden, true);
assert.equal(items[1].hidden, false);
assert.equal(items[1].getAttribute('aria-pressed'), 'true');
assert.equal(workspace.querySelector('[data-detail-title]').textContent, 'Beta');
assert.equal(workspace.querySelector('[data-detail-source]').hidden, true);
assert.equal(workspace.querySelector('[data-copy-finding="title"]').dataset.copyValue, 'Beta');
workspace.querySelector('[data-copy-finding="location"]').click();

workspace.querySelector('[data-finding-search]').value = '';
workspace.querySelector('[data-finding-search]').dispatchEvent(new dom.window.Event('input'));
items[0].click();
assert.equal(document.querySelector('details').open, false);
assert.equal(document.querySelector('.wt-code-line').classList.contains('wt-code-line-target'), false);
workspace.querySelector('[data-detail-source]').click();
assert.equal(document.querySelector('details').open, true);
assert.equal(document.querySelector('.wt-code-line').classList.contains('wt-code-line-target'), true);

document.body.insertAdjacentHTML('afterbegin', workspaceMarkup('htmx-workspace'));
dom.window.eval(workspaceScript);
assert.equal(document.getElementById('htmx-workspace').dataset.initialized, 'true');

setImmediate(() => {
  assert.equal(copiedValue, 'src/B.java:9');
  assert.equal(workspace.querySelector('[data-copy-status]').textContent, 'Copied to clipboard.');
  console.log('Finding workspace jsdom test passed');
});

const pagedDom = new JSDOM(`<!doctype html><body>${workspaceMarkup('paged-workspace', 23)}</body>`,
  {runScripts: 'dangerously'});
pagedDom.window.matchMedia = () => ({matches: true});
pagedDom.window.requestAnimationFrame = callback => callback();
pagedDom.window.eval(workspaceScript);

const pagedWorkspace = pagedDom.window.document.getElementById('paged-workspace');
const pagedItems = Array.from(pagedWorkspace.querySelectorAll('[data-finding-item]'));
const previous = pagedWorkspace.querySelector('[data-finding-previous]');
const next = pagedWorkspace.querySelector('[data-finding-next]');
const range = pagedWorkspace.querySelector('[data-finding-range]');

assert.equal(pagedItems.filter(item => !item.hidden).length, 10,
  'the first page should expose exactly ten findings');
assert.equal(range.textContent, '1–10 of 23');
assert.equal(previous.disabled, true);
assert.equal(next.disabled, false);

next.click();
assert.equal(pagedItems.filter(item => !item.hidden).length, 10);
assert.equal(range.textContent, '11–20 of 23');
assert.equal(previous.disabled, false);

pagedItems[14].click();
assert.equal(pagedItems[14].getAttribute('aria-pressed'), 'true');
pagedWorkspace.querySelector('[data-finding-search]').value = 'Finding 15';
pagedWorkspace.querySelector('[data-finding-search]').dispatchEvent(
  new pagedDom.window.Event('input'));
assert.equal(range.textContent, '1–1 of 1', 'filtering should reset pagination to page one');
assert.equal(pagedItems[14].hidden, false, 'a selected matching finding should remain visible');
assert.equal(pagedItems[14].getAttribute('aria-pressed'), 'true',
  'a selected matching finding should remain selected');

pagedWorkspace.querySelector('[data-finding-search]').value = 'Finding 2';
pagedWorkspace.querySelector('[data-finding-search]').dispatchEvent(
  new pagedDom.window.Event('input'));
assert.equal(pagedItems[1].getAttribute('aria-pressed'), 'true',
  'the first visible result should be selected when the prior selection is filtered out');

pagedWorkspace.querySelector('[data-finding-search]').value = 'no such finding';
pagedWorkspace.querySelector('[data-finding-search]').dispatchEvent(
  new pagedDom.window.Event('input'));
assert.equal(range.textContent, '0 of 0');
assert.equal(pagedWorkspace.querySelector('.wt-finding-detail').hidden, true);
assert.equal(pagedWorkspace.querySelector('[data-detail-title]').textContent, '');
assert.equal(pagedWorkspace.querySelector('[data-finding-item].is-selected'), null);
assert.equal(pagedWorkspace.querySelector('[data-finding-empty]').hidden, false);
assert.equal(previous.disabled, true);
assert.equal(next.disabled, true);

const materialMarkup = workspaceMarkup('material-workspace')
  .replace('<input data-finding-search>',
    '<md-outlined-text-field data-finding-search></md-outlined-text-field>')
  .replace('<select data-finding-severity><option value="">All</option><option value="1">High</option></select>',
    '<md-outlined-select data-finding-severity><md-select-option value=""></md-select-option>' +
    '<md-select-option value="1"></md-select-option></md-outlined-select>')
  .replace('<select data-finding-location><option value="">All</option></select>',
    '<md-outlined-select data-finding-location><md-select-option value=""></md-select-option>' +
    '</md-outlined-select>');
const materialDom = new JSDOM(`<!doctype html><body>${materialMarkup}</body>`,
  {runScripts: 'dangerously'});
materialDom.window.matchMedia = () => ({matches: true});
materialDom.window.requestAnimationFrame = callback => callback();
materialDom.window.eval(workspaceScript);
const materialWorkspace = materialDom.window.document.getElementById('material-workspace');
const materialLocations = materialWorkspace.querySelectorAll(
  '[data-finding-location] md-select-option');
assert.equal(materialLocations.length, 3,
  'material location filter should receive the two report locations');
assert.equal(materialLocations[1].querySelector('[slot="headline"]').textContent, 'src/A.java');
materialWorkspace.querySelector('[data-finding-severity]').value = '1';
materialWorkspace.querySelector('[data-finding-severity]').dispatchEvent(
  new materialDom.window.Event('change'));
assert.equal(materialWorkspace.querySelectorAll('[data-finding-item]:not([hidden])').length, 1,
  'material select values should drive the same filtering behavior');

// A qualified AWS location shows verified source as code lines when its finding opens.
{
  const providerMarkup = workspaceMarkup('provider-workspace')
    .replace('data-title="Alpha"', 'data-title="Alpha" data-provider-detail-url="/reposcan/report/12/aws/findings/abc?page=0"')
    .replace('</aside>', '<section data-provider-detail></section></aside>');
  const providerDom = new JSDOM(`<!doctype html><body>${providerMarkup}</body>`,
    {url: 'https://watchtower.example/reposcan/report/12', runScripts: 'dangerously'});
  providerDom.window.matchMedia = () => ({matches: true});
  providerDom.window.requestAnimationFrame = callback => callback();
  const requested = [];
  providerDom.window.fetch = async url => {
    requested.push(String(url));
    return {ok: true, json: async () => String(url).includes('/source?')
      ? {file: 'src/A.java', commit: 'abc123', startLine: 4, flaggedStartLine: 4, requestedEndLine: 4,
        lines: ['if (unsafe) reject();'], truncated: false}
      : {live: true, evidence: {riskType: 'SECURITY_MISCONFIGURATION', nativeSeverity: 'MEDIUM',
        locations: [{file: 'src/A.java', startLine: 4, endLine: 4}], sourceLocations: [0], sensitive: false}}};
  };
  providerDom.window.eval(workspaceScript);
  setImmediate(() => {
    const details = providerDom.window.document.querySelector('[data-provider-detail]');
    assert.ok(requested.some(url => url.includes('/source?location=0&page=0') || url.includes('/source?page=0&location=0')));
    assert.equal(details.querySelector('.wt-code-text').textContent, 'if (unsafe) reject();');
    assert.equal(details.querySelector('.wt-code-lineno').textContent, '4');
    providerDom.window.close();
  });
}

// The file filter as one chip menu ("All files 2 ▾") over a hidden value, and the engine's own
// wording as a chip whose hover text follows the selected finding (UAT walkthrough, 2026-10-16).
{
  const chipMarkup = workspaceMarkup('chip-workspace')
    .replace('<select data-finding-location><option value="">All</option></select>',
      '<details data-finding-location-menu data-all-label="All files"><summary>' +
      '<span data-finding-location-label>All files</span><span data-finding-location-count>0</span></summary>' +
      '<div data-finding-location-options><button type="button" class="wt-menu-item" value="" aria-checked="true">All files</button></div>' +
      '</details><input type="hidden" value="" data-finding-location>')
    .replace('data-title="Beta"', 'data-title="Beta" data-original-guidance="Engine said: Beta {0}"')
    .replace('<div class="wt-finding-detail-heading"><span class="wt-sev"></span></div>',
      '<div class="wt-finding-detail-heading"><span class="wt-sev"></span>' +
      '<span data-original-message tabindex="0" hidden>Engine message</span></div>');
  const chipDom = new JSDOM(`<!doctype html><body>${chipMarkup}</body>`, {runScripts: 'dangerously'});
  chipDom.window.matchMedia = () => ({matches: true});
  chipDom.window.requestAnimationFrame = callback => callback();
  chipDom.window.eval(workspaceScript);
  const chipWorkspace = chipDom.window.document.getElementById('chip-workspace');
  const menu = chipWorkspace.querySelector('[data-finding-location-menu]');
  assert.equal(menu.querySelector('[data-finding-location-count]').textContent, '2');
  const fileOptions = menu.querySelectorAll('.wt-menu-item');
  assert.deepEqual(Array.from(fileOptions).map(o => o.textContent), ['All files', 'src/A.java', 'src/B.java']);
  menu.open = true;
  fileOptions[2].dispatchEvent(new chipDom.window.MouseEvent('click', {bubbles: true}));
  assert.equal(chipWorkspace.querySelector('[data-finding-location]').value, 'src/B.java');
  assert.equal(menu.open, false);
  assert.equal(menu.querySelector('[data-finding-location-label]').textContent, 'src/B.java');
  assert.equal(fileOptions[2].getAttribute('aria-checked'), 'true');
  const shown = chipWorkspace.querySelectorAll('[data-finding-item]:not([hidden])');
  assert.equal(shown.length, 1, 'the chip filters the list to that file');
  shown[0].dispatchEvent(new chipDom.window.MouseEvent('click', {bubbles: true}));
  const engine = chipWorkspace.querySelector('[data-original-message]');
  assert.equal(engine.hidden, false);
  assert.equal(engine.getAttribute('data-tip'), 'Engine said: Beta {0}');
  assert.equal(engine.getAttribute('aria-label'), 'Engine message: Engine said: Beta {0}');
  fileOptions[0].dispatchEvent(new chipDom.window.MouseEvent('click', {bubbles: true}));
  assert.equal(menu.querySelector('[data-finding-location-label]').textContent, 'All files');
  assert.equal(chipWorkspace.querySelectorAll('[data-finding-item]:not([hidden])').length, 2);
  chipDom.window.close();
}

// "Rule changed" / "Rule deleted": one chip in the detail heading, hover text from the selected
// finding, hidden for a finding whose rule is untouched.
{
  const changeMarkup = workspaceMarkup('rule-change-workspace')
    .replace('data-title="Beta"', 'data-title="Beta" data-rule-change-label="Rule changed"' +
      ' data-rule-change-tip="The rule was edited after this scan."')
    .replace('<div class="wt-finding-detail-heading"><span class="wt-sev"></span></div>',
      '<div class="wt-finding-detail-heading"><span class="wt-sev"></span>' +
      '<span data-rule-change tabindex="0" hidden><span data-rule-change-text></span></span></div>');
  const changeDom = new JSDOM(`<!doctype html><body>${changeMarkup}</body>`, {runScripts: 'dangerously'});
  changeDom.window.matchMedia = () => ({matches: true});
  changeDom.window.requestAnimationFrame = callback => callback();
  changeDom.window.eval(workspaceScript);
  const changeWorkspace = changeDom.window.document.getElementById('rule-change-workspace');
  const items = changeWorkspace.querySelectorAll('[data-finding-item]');
  const chip = changeWorkspace.querySelector('[data-rule-change]');
  const clickItem = item => item.dispatchEvent(new changeDom.window.MouseEvent('click', {bubbles: true}));
  clickItem(items[1]);
  assert.equal(chip.hidden, false);
  assert.equal(chip.querySelector('[data-rule-change-text]').textContent, 'Rule changed');
  assert.equal(chip.getAttribute('data-tip'), 'The rule was edited after this scan.');
  assert.equal(chip.getAttribute('aria-label'), 'Rule changed. The rule was edited after this scan.');
  clickItem(items[0]);
  assert.equal(chip.hidden, true, 'a finding whose rule is untouched shows no chip');
  changeDom.window.close();
}

// Live verification: a status chip in the detail heading (description in its popover) and a
// "Verify live" button in the action row - no section of its own.
{
  const verifyMarkup = workspaceMarkup('verify-workspace')
    .replace('data-title="Alpha"', 'data-title="Alpha" data-verify-id="7" data-verify-status="LIVE"' +
      ' data-verify-label="Live" data-verify-description="The provider accepted it."' +
      ' data-verify-can-request="true"')
    .replace('<div class="wt-finding-detail-heading"><span class="wt-sev"></span></div>',
      '<div class="wt-finding-detail-heading"><span class="wt-sev"></span>' +
      '<span data-detail-verify><span data-detail-verify-status></span>' +
      '<span data-detail-verify-description></span></span></div>')
    .replace('<a data-detail-url></a>',
      '<a data-detail-url></a><form data-detail-verify-form>' +
      '<input data-detail-verify-id><button type="submit">Verify live</button></form>');
  const verifyDom = new JSDOM(`<!doctype html><body>${verifyMarkup}</body>`,
    {runScripts: 'dangerously'});
  verifyDom.window.matchMedia = () => ({matches: true});
  verifyDom.window.requestAnimationFrame = callback => callback();
  verifyDom.window.eval(workspaceScript);
  const verifyWorkspace = verifyDom.window.document.getElementById('verify-workspace');
  const [alpha, beta] = verifyWorkspace.querySelectorAll('[data-finding-item]');
  const chip = verifyWorkspace.querySelector('[data-detail-verify]');
  const form = verifyWorkspace.querySelector('[data-detail-verify-form]');

  alpha.click();
  assert.equal(chip.hidden, false, 'a verifiable finding shows its status chip');
  assert.equal(chip.querySelector('[data-detail-verify-status]').textContent, 'Live');
  assert.equal(chip.querySelector('[data-detail-verify-status]').dataset.status, 'LIVE');
  assert.equal(chip.querySelector('[data-detail-verify-description]').textContent,
    'The provider accepted it.');
  assert.equal(form.hidden, false, 'Verify live sits in the action row');
  assert.equal(form.querySelector('[data-detail-verify-id]').value, '7');

  beta.click();
  assert.equal(chip.hidden, true, 'other findings show no verification chip');
  assert.equal(form.hidden, true, 'and no Verify live button');
  console.log('Finding verification jsdom test passed');
}

// Returning from review restores the selected occurrence, filters and its page.
{
 const returned = new JSDOM(`<!doctype html><body>${workspaceMarkup('returned', 23)}</body>`, {
  runScripts: 'dangerously', url: 'https://watchtower.test/scan/report/1?reviewFinding=22&reviewSearch=Finding&reviewSeverity=1'
 });
 returned.window.matchMedia = () => ({matches: true});
 returned.window.eval(workspaceScript);
 const root = returned.window.document.querySelector('[data-finding-workspace]');
 assert.equal(root.querySelector('[data-finding-search]').value, 'Finding');
 assert.equal(root.querySelector('[data-finding-severity]').value, '1');
 assert.equal(root.querySelector('[data-finding-item].is-selected').dataset.feedbackKey, '22');
 assert.equal(root.querySelector('[data-finding-item].is-selected').hidden, false);
 assert.equal(root.querySelector('[data-finding-range]').textContent, '11–11 of 11');
}

// Severity toggle chips (UAT walkthrough 2026-10-15): each chip shows or hides its severity; the
// visible set lives in the same filter value, so a review return link still restores it.
{
 const markup = workspaceMarkup('toggles', 4)
  .replace('<select data-finding-severity><option value="">All</option><option value="1">High</option></select>',
   '<input type="hidden" data-finding-severity value=""><button data-severity-chip="1" aria-pressed="true">High</button>' +
   '<button data-severity-chip="3" aria-pressed="true">Medium</button>');
 const page = new JSDOM(`<!doctype html><body>${markup}</body>`, {runScripts: 'dangerously', url: 'https://watchtower.test/scan/report/1'});
 page.window.matchMedia = () => ({matches: true});
 page.window.eval(workspaceScript);
 const root = page.window.document.querySelector('[data-finding-workspace]');
 const high = root.querySelector('[data-severity-chip="1"]');
 const medium = root.querySelector('[data-severity-chip="3"]');
 const visible = () => Array.from(root.querySelectorAll('[data-finding-item]')).filter(item => !item.hidden).length;
 assert.equal(visible(), 4);
 medium.click();
 assert.equal(root.querySelector('[data-finding-severity]').value, '1');
 assert.equal(medium.getAttribute('aria-pressed'), 'false');
 assert.equal(visible(), 2, 'hiding Medium leaves the two High findings');
 high.click();
 assert.equal(root.querySelector('[data-finding-severity]').value, '-');
 assert.equal(visible(), 0, 'hiding every severity shows none');
 medium.click(); high.click();
 assert.equal(root.querySelector('[data-finding-severity]').value, '', 'all visible again means no filter');
 assert.equal(visible(), 4);
 assert.equal(high.getAttribute('aria-pressed'), 'true');
}
console.log('Severity toggle chips passed');

// Image (package) findings: selecting one shows its CVSS chip and the vector in plain words, while
// a click on the vector still copies the raw code (UAT walkthrough, 2026-10-16).
{
  const pkg = (id, extra) => `<button data-finding-item id="${id}" data-severity="1" data-location="openssl"
      data-location-label="openssl" data-title="${id}" data-guidance="g" ${extra}>
      <span class="wt-sev wt-sev-1">High</span></button>`;
  const cvssDom = new JSDOM(`<!doctype html><body><section data-finding-workspace>
    <input data-finding-search><input data-finding-severity value=""><select data-finding-location><option value="">All</option></select>
    <span data-finding-status></span><div data-finding-empty hidden></div>
    <div data-finding-list-viewport>
      ${pkg('CVE-1', 'class="is-selected" data-score="5.0" data-vector="AV:N/AC:L/Au:N/C:N/I:N/A:P" data-cvss-label="CVSS 5.0 · Medium" data-cvss-key="3" data-cvss-tip="CVSS base score 5.0 out of 10" data-vector-text="Network · No auth · Availability" data-vector-tip="Vector AV:N/AC:L/Au:N/C:N/I:N/A:P. Click to copy."')}
      ${pkg('CVE-2', 'data-score="N/A" data-cvss-label="No CVSS" data-cvss-key="UNKNOWN" data-cvss-tip="The advisory has no CVSS score"')}
    </div>
    <nav data-finding-pagination><span data-finding-range></span><button data-finding-previous></button><button data-finding-next></button></nav>
    <aside class="wt-finding-detail">
      <div class="wt-finding-detail-heading"><span class="wt-sev"></span></div>
      <h3 data-detail-title></h3><button data-copy-finding="title"></button>
      <button data-copy-finding="location"><span data-detail-location></span></button>
      <span class="wt-sev wt-cvss-chip" data-detail-cvss data-detail-score></span>
      <button data-copy-finding="vector" data-detail-vector-row><span data-detail-vector></span></button>
      <p data-detail-guidance></p><span data-copy-status></span><a data-detail-url></a>
    </aside></section></body>`, {runScripts: 'dangerously'});
  cvssDom.window.matchMedia = () => ({matches: true});
  cvssDom.window.HTMLElement.prototype.scrollIntoView = function () {};
  cvssDom.window.eval(workspaceScript);
  const doc = cvssDom.window.document;
  const [scored, unscored] = doc.querySelectorAll('[data-finding-item]');
  scored.click();
  const cvss = doc.querySelector('[data-detail-cvss]');
  const vectorChip = doc.querySelector('[data-detail-vector-row]');
  assert.equal(cvss.textContent, 'CVSS 5.0 · Medium');
  assert.ok(cvss.classList.contains('wt-sev-3'), 'the CVSS chip is coloured by its band');
  assert.equal(doc.querySelector('[data-detail-vector]').textContent, 'Network · No auth · Availability');
  assert.equal(vectorChip.dataset.copyValue, 'AV:N/AC:L/Au:N/C:N/I:N/A:P', 'a click copies the raw vector');
  assert.equal(vectorChip.hidden, false);
  unscored.click();
  assert.equal(cvss.hidden, false, 'an advisory without a score still says so');
  assert.equal(cvss.textContent, 'No CVSS');
  assert.ok(cvss.classList.contains('wt-sev-UNKNOWN'));
  assert.equal(vectorChip.hidden, true);
  console.log('Finding workspace: package findings show CVSS and vector chips');
}

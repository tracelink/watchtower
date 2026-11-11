const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

// AwsReport board (2026-10-22): one workspace with a Scanner filter; an AWS finding's detail shows
// chips (scanner, confidence, validation), a chip per location that loads the code around it, and
// the AWS ids in a Technical details fold.
const script = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/finding-workspace.js'), 'utf8');
const key = 'a'.repeat(64);
const endpoint = `/reposcan/report/11/aws/findings/${key}?page=0`;
const dom = new JSDOM(`<!doctype html><body><section data-aws-titles-url="/reposcan/report/11/aws/titles?page=0">
  <section data-finding-workspace><input data-finding-search><input type="hidden" data-finding-severity value="">
  <input type="hidden" data-finding-location value=""><span data-finding-status></span><span data-finding-total></span>
  <details data-finding-scanner-menu><summary><span data-finding-scanner-label>All scanners</span></summary>
    <div data-finding-scanner-options><button class="wt-menu-item" value="">All</button>
      <button class="wt-menu-item" value="aws">AWS</button><button class="wt-menu-item" value="other">Other</button></div></details>
  <input type="hidden" value="" data-finding-scanner>
  <div data-finding-scanner-empty hidden><p data-finding-scanner-empty-text></p></div>
  <div data-split-workspace>
  <div data-finding-empty hidden></div><div data-finding-list-viewport>
    <button id="aws-${key}" data-finding-item data-scanner-group="aws" data-severity="HIGH" data-location="Location unavailable"
      data-location-label="Location unavailable" data-title="Privilege escalation" data-guidance="AWS Security Agent reports a possible privilege escalation risk"
      data-provider-detail-url="${endpoint}" data-source-action="false" aria-pressed="true">
      <span class="wt-finding-item-topline"><span class="wt-sev">High</span><strong>Privilege escalation</strong></span>
      <span class="wt-finding-location">Location unavailable</span></button></div>
    <div data-finding-pagination><span data-finding-range></span><button data-finding-previous></button><button data-finding-next></button></div>
    <aside class="wt-finding-detail"><div class="wt-finding-detail-heading"><span class="wt-sev">High</span>
      <span data-detail-scanner><span data-detail-scanner-icon></span><span data-detail-scanner-name></span></span></div>
      <h3 data-detail-title></h3><span data-detail-location></span><p data-detail-guidance></p>
      <div data-provider-chips hidden></div>
      <div data-detail-cvss><span data-detail-score></span></div><div data-detail-vector-row><span data-detail-vector></span></div>
      <section data-provider-detail hidden></section><span data-detail-help><a>info</a></span>
      <a data-detail-url><span data-detail-url-icon>menu_book</span><span data-detail-url-label></span></a></aside></div></section></section></body>`,
  {url: 'https://watchtower.example/', runScripts: 'dangerously'});
dom.window.matchMedia = () => ({matches: true});
dom.window.requestAnimationFrame = callback => callback();
const pathInRepo = 'wt-test-core/src/main/java/example/ImageScanResultService.java';
const requests = [];
let secretsScanned = true;
dom.window.fetch = async url => {
  requests.push(String(url));
  if (String(url).includes('/titles')) return {ok: true, json: async () => ({[key]: {
    title: 'Privilege escalation', file: pathInRepo, line: 106
  }})};
  if (String(url).includes('/source')) return {ok: true, json: async () => ({
    file: pathInRepo, commit: 'b'.repeat(40), startLine: 105, flaggedStartLine: 106, requestedEndLine: 107,
    lines: ['// before', 'if (errors != null) {', '[hidden: flagged by a secrets scanner]'], truncated: false, maskedLines: [107], secretsScanned
  })};
  return {ok: true, json: async () => ({
    live: true, title: 'Privilege escalation',
    description: 'A failed scan is served as clean.\n\nThe CI gate reads the status.',
    reasoning: null, evidence: {findingId: 'f-one', jobId: 'cj-one', riskType: 'PRIVILEGE_ESCALATION', nativeSeverity: 'HIGH',
      confidence: 'MEDIUM', validationStatus: 'NOT_VALIDATED', sensitive: false,
      locations: [{file: pathInRepo, startLine: 106, endLine: 107}, {file: 'pom.xml', startLine: 61, endLine: 64}], sourceLocations: [0],
      omissions: ['Provider narrative and source are fetched on demand']}
  })};
};
dom.window.eval(script);

const settle = () => new Promise(resolve => setTimeout(resolve, 0));

(async () => {
  await settle(); await settle();
  const doc = dom.window.document;
  const workspace = doc.querySelector('[data-finding-workspace]');
  assert.equal(workspace.querySelector('[data-detail-title]').textContent, 'Privilege escalation');
  assert.equal(workspace.querySelector('[data-detail-location]').textContent, `${pathInRepo}:106`);
  assert.equal(workspace.querySelector('[data-detail-help]').hidden, true, 'no stray info icon on AWS findings');
  assert.equal(workspace.querySelector('[data-detail-scanner]').hidden, true, 'scanner shown once, in the chip row');
  assert.equal(workspace.querySelector('[data-detail-url-icon]').textContent, 'open_in_new');

  const chips = workspace.querySelector('[data-provider-chips]');
  assert.equal(chips.hidden, false);
  assert.match(chips.textContent, /AWS Security Agent/);
  assert.match(chips.textContent, /Confidence: Medium/);
  assert.match(chips.textContent, /Not validated/);

  const evidence = workspace.querySelector('[data-provider-detail]');
  assert.match(evidence.textContent, /Locations · View source/);
  assert.equal(evidence.textContent.includes('AWS severity:'), false, 'facts are chips, not a sentence');
  assert.equal(evidence.textContent.includes('Provider narrative and source are fetched'), false);
  const locationChips = evidence.querySelectorAll('.wt-provider-location');
  assert.equal(locationChips.length, 2);
  assert.equal(locationChips[0].textContent, 'codeImageScanResultService.java:106–107');
  assert.equal(locationChips[1].querySelector('.material-icons').textContent, 'lock');
  // The first location with source loads on its own.
  assert.equal(requests.some(url => url.includes('/source') && url.includes('location=0')), true);
  const lines = Array.from(evidence.querySelectorAll('.wt-code-line'));
  assert.equal(lines.length, 3);
  assert.equal(lines[1].classList.contains('wt-code-line-violation'), true);
  assert.equal(lines[2].classList.contains('wt-code-line-masked'), true);
  assert.match(evidence.querySelector('.wt-provider-source-head').textContent, /at commit bbbbbbb/);
  assert.match(evidence.querySelector('.wt-provider-source-head').textContent, /Not stored/);
  assert.match(evidence.querySelector('.wt-provider-source-head').textContent, /Secrets masked/, 'a secrets scanner ran on this scan');

  locationChips[1].click();
  assert.match(evidence.querySelector('.wt-provider-source').textContent, /can’t be shown/);
  // No secrets scanner ran on this scan: nothing was checked, so the panel must not say lines are masked.
  secretsScanned = false;
  locationChips[0].click();
  await settle(); await settle();
  assert.doesNotMatch(evidence.querySelector('.wt-provider-source-head').textContent, /Secrets masked/);
  assert.match(evidence.querySelector('.wt-provider-source-head').textContent, /Not stored/);

  const technical = Array.from(evidence.querySelectorAll('details')).find(d => d.querySelector('summary').textContent === 'Technical details');
  assert.ok(technical);
  assert.ok(technical.querySelector('[data-copy-text="f-one"]'));
  assert.ok(technical.querySelector('[data-copy-text="cj-one"]'));

  // Scanner filter: "Other scanners" with nothing shows the usual No findings state.
  doc.querySelector('[data-finding-scanner-options] [value="other"]').click();
  assert.equal(doc.querySelector('[data-finding-scanner-empty]').hidden, false);
  assert.equal(doc.querySelector('[data-split-workspace]').hidden, true);
  assert.equal(doc.querySelector('[data-finding-scanner-label]').textContent, 'Other scanners');
  doc.querySelector('[data-finding-scanner-options] [value="aws"]').click();
  assert.equal(doc.querySelector('[data-finding-scanner-empty]').hidden, true);
  assert.equal(doc.querySelector('[data-split-workspace]').hidden, false);
  console.log('AWS finding workspace: chips, location source and scanner filter passed');
})().catch(error => { console.error(error); process.exitCode = 1; });

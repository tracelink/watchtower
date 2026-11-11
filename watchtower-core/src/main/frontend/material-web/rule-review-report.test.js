const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const resources = path.resolve(__dirname, '../../resources');
const template = fs.readFileSync(path.join(resources, 'templates/rules/review-reports.html'), 'utf8');
const dialogMarkup = template;

function report(trigger) {
  return {
    settings: {enabled: true, weekday: 1, version: 3},
    report: {id: 'r1', period: '2026-W42', trigger, actor: 'steward', created_at: Date.UTC(2026, 9, 12),
      summary: {counts: {rules: 4, attention: 1, insufficient_data: 2}, attention_truncated: false,
        attention: [{rule_id: 7, name: '<img src=x onerror=alert(1)>', module: 'Regex', owner: null, open_reviews: 1,
          reasons: [{code: 'CONFIRMED_NOISE', reviewed_sample: 8, false_positives: 6}, {code: 'NO_CWE'}]}],
        themes_note: 'Suggestions only.',
        ai_naming: {state: 'ON', named: 1, themes: 2, message: 'AI names are suggestions.'},
        themes: [{rule_id: 7, name: 'Hard-coded token', module: 'Regex', source: 'bypass', category: 'TEST_CODE', records: 3, people: 2, terms: ['generated', '<b>client</b>'],
          ai: {status: 'NAMED', name: '<img src=x onerror=alert(2)>', cause: 'TEST_OR_GENERATED_CODE', cause_label: 'matches test or generated code',
            explanation: 'Dummy values in generated clients.', model: 'fixture-model', text_sent: false, created_at: Date.UTC(2026, 9, 13)}},
          {rule_id: 99, name: null, module: null, source: 'review_outcome', category: 'REJECTED:noise', records: 3, people: 1, terms: [],
            ai: {status: 'REJECTED', model: 'fixture-model', created_at: Date.UTC(2026, 9, 13)}}],
        matrix: {cwe_edition: '2024', note: 'Not proof of coverage.', languages: ['any', 'java'],
          rows: [{cwe: 'CWE-79', rank: 1, name: 'Cross-site Scripting', cells: {any: {rules: 2, ran_30d: 1}}},
            {cwe: 'CWE-787', rank: 2, name: 'Out-of-bounds Write', cells: {}},
            {cwe: 'Unclassified', rank: null, name: 'Rules without a CWE', cells: {java: {rules: 1, ran_30d: 0}}}]}}}
  };
}

async function setup(canModify) {
  const dom = new JSDOM(`<body><md-outlined-button data-rule-report-open>Review report</md-outlined-button>${dialogMarkup}</body>`,
    {url: 'https://watchtower.example/rule/edit/regex', runScripts: 'dangerously'});
  const w = dom.window;
  const dialog = w.document.querySelector('[data-rule-report-dialog]');
  Object.assign(dialog.dataset, {csrfHeader: 'X-CSRF-TOKEN', csrfToken: 'fixture', canModify: String(canModify)});
  dialog.show = async () => {};
  dialog.close = () => {};
  const requests = [];
  const upstream = [{id: 'u1', module: 'Betterleaks', created_at: Date.UTC(2026, 9, 12), version: 0, held: 2, check_status: 'FAILED', approved_at: null, approved_by: null,
    added: [{rule_id: 3, name: '<i>stripe-key</i>'}, {rule_id: 4, name: 'slack-token'}], changed: [{rule_id: 2, name: 'github-pat'}], removed: ['aws-key'],
    check: [{rule_id: 2, name: 'github-pat', status: 'FAILED_EXPECTATION'}]}];
  w.fetch = async (url, options = {}) => {
    requests.push({url, options});
    if (url === '/rule/upstream-updates') return {ok: true, status: 200, json: async () => upstream};
    if (url === '/rule/upstream-updates/u1/approve') return {ok: true, status: 200, json: async () => ({updates: [Object.assign({}, upstream[0], {approved_at: 1, approved_by: 'steward', version: 1})]})};
    if (url === '/rule/review-report/run' && requests.filter(r => r.url === url).length > 1) {
      return {ok: false, status: 429, json: async () => ({error: 'A report was run in the last 5 minutes'})};
    }
    if (url === '/rule/review-report/settings') {
      const sent = JSON.parse(options.body);
      return {ok: true, status: 200, json: async () => Object.assign(report('SCHEDULED'), {settings: {enabled: sent.enabled, weekday: sent.weekday, version: 4}})};
    }
    return {ok: true, status: 200, json: async () => report(url.endsWith('/run') ? 'MANUAL' : 'SCHEDULED')};
  };
  w.eval(fs.readFileSync(path.join(resources, 'static/scripts/rule-review-report.js'), 'utf8'));
  const settle = () => new Promise(resolve => setTimeout(resolve, 0));
  // Dedicated pages initialize once on navigation.
  await settle();
  return {w, dialog, requests, settle};
}

async function main() {
  const viewer = await setup(false);
  const q = name => viewer.dialog.querySelector('[data-rule-report-' + name + ']');
  // The report's name and counts are drawn on the server; the status line stays free for actions.
  assert.equal(q('status').textContent, '');
  assert.equal(q('schedule-label').textContent, 'Weekly · Monday (UTC)');
  assert.equal(q('settings').hidden, true);
  assert.equal(q('run').hidden, true);
  const themeRows = q('themes').querySelectorAll('li');
  assert.equal(themeRows.length, 2);
  assert.equal(themeRows[0].querySelector('a').getAttribute('href'), '/rule/edit/regex/7');
  assert.match(themeRows[0].textContent, /PR bypasses.*test code.*3 records from 2 people · generated, <b>client<\/b>/);
  assert.equal(q('themes').querySelector('b'), null);
  // R5.2b: AI text is labelled, rendered as text, explained in a tooltip; one status chip.
  assert.match(themeRows[0].textContent, /AI suggestion: <img src=x onerror=alert\(2\)>.*likely: matches test or generated code/);
  assert.equal(q('themes').querySelector('img'), null);
  assert.match(themeRows[0].querySelector('[title*="Dummy values"]').title, /fixture-model.*named from counts only/);
  assert.match(themeRows[1].textContent, /AI output rejected/);
  const namingChip = q('themes').querySelector(':scope > .wt-status-chip');
  assert.equal(namingChip.textContent, 'AI names: 1 of 2');
  assert.equal(namingChip.title, 'AI names are suggestions.');
  assert.match(themeRows[1].textContent, /^Rule 99 · Review decisions/);
  const rows = q('matrix').querySelectorAll('tbody tr');
  assert.equal(rows.length, 3);
  assert.equal(rows[0].querySelector('td').textContent, '2 rules · 1 ran');
  assert.equal(rows[1].className, 'is-gap');
  assert.equal(rows[2].className, '');
  assert.equal(viewer.requests[0].options.method, undefined);
  const update = q('upstream').querySelector('li');
  assert.match(update.textContent, /Betterleaks · .* · 2 new, 1 changed, 1 removed · a reviewed test no longer matches its label/);
  assert.match(update.textContent, /2 new rules not blocking yet/);
  assert.match(update.textContent, /New: <i>stripe-key<\/i>, slack-token/);
  assert.equal(q('upstream').querySelector('i'), null);
  assert.match(update.textContent, /Removed \(retired\): aws-key/);
  assert.match(update.textContent, /Check rule github-pat: its reviewed tests no longer pass/);
  assert.equal(q('upstream').querySelector('[data-rule-report-approve]'), null, 'read-only viewers cannot release held rules');
  viewer.w.close();

  const steward = await setup(true);
  const s = name => steward.dialog.querySelector('[data-rule-report-' + name + ']');
  assert.equal(s('settings').hidden, false);
  s('upstream').querySelector('[data-rule-report-approve]').click();
  await steward.settle(); await steward.settle();
  const approved = steward.requests.find(r => r.url === '/rule/upstream-updates/u1/approve');
  assert.deepEqual(JSON.parse(approved.options.body), {version: 0});
  assert.equal(approved.options.headers['X-CSRF-TOKEN'], 'fixture');
  assert.match(s('upstream').textContent, /Approved by steward/);
  assert.equal(s('upstream').querySelector('[data-rule-report-approve]'), null);
  assert.equal(s('run').hidden, false);
  s('run').click();
  await steward.settle();
  const run = steward.requests.find(r => r.url === '/rule/review-report/run');
  assert.equal(run.options.method, 'POST');
  assert.equal(run.options.headers['X-CSRF-TOKEN'], 'fixture');
  assert.match(s('status').textContent, /Report generated/);
  s('run').click();
  await steward.settle();
  assert.match(s('status').textContent, /last 5 minutes/);
  s('enabled').checked = false;
  s('weekday').value = '5';
  s('settings').dispatchEvent(new steward.w.Event('submit', {bubbles: true, cancelable: true}));
  await steward.settle();
  const saved = steward.requests.find(r => r.url === '/rule/review-report/settings');
  assert.deepEqual(JSON.parse(saved.options.body), {enabled: false, weekday: 5, version: 3});
  assert.equal(saved.options.headers['X-CSRF-TOKEN'], 'fixture');
  assert.equal(s('status').textContent, 'Schedule saved.');
  assert.equal(s('schedule-label').textContent, 'Schedule off', 'the schedule chip follows the saved schedule');
  steward.w.close();
  console.log('Rule review report: safe rendering, gaps, read-only viewers, CSRF and rate limit passed');
}
main().catch(error => {console.error(error); process.exitCode = 1;});

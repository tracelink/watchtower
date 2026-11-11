const {test, expect} = require('@playwright/test');
const fs = require('node:fs');
const path = require('node:path');
const resources = path.resolve(__dirname, '../../resources');
const shell = fs.readFileSync(path.join(resources, 'templates/fragments/container.html'), 'utf8');
const drawer = shell.match(/<wt-assistant-drawer[\s\S]*?<\/wt-assistant-drawer>/)[0];

test('candidate dialog reviews exact evidence and keeps promotion explicit', async ({page}, testInfo) => {
  const template = fs.readFileSync(path.join(resources, 'templates/rules/rule-edit.html'), 'utf8');
  const fragment = template.match(/<md-dialog[^>]*data-rule-candidates-dialog[\s\S]*?<\/md-dialog>/)[0];
  const revision = 'a'.repeat(64), next = 'b'.repeat(64), hash = 'c'.repeat(64);
  let promotion;
  const candidate = {candidate_id: 'candidate-id', rule_id: 42, base_revision: revision, revision: next,
    status: 'SHADOW', version: 2, definition_json: JSON.stringify({regexPattern: '<img src=x onerror=alert(1)>', fileExtension: '.txt'}), rationale: 'Narrow reviewed noisy alternative'};
  await page.route('https://watchtower.example/**', route => {
    const url = new URL(route.request().url());
    if (url.pathname === '/') return route.fulfill({contentType: 'text/html', body: '<body></body>'});
    let body = candidate;
    if (url.pathname.includes('/workspace/')) body = {ruleId: 42, revision, testingAvailable: true,
      editableFields: ['regexPattern', 'fileExtension', 'message'], definition: {regexPattern: 'risky|unsafe', fileExtension: '.txt', message: 'Reviewed case'}, candidates: [candidate], fixtures: [], history: []};
    if (url.pathname.endsWith('/runs')) body = [{run_id: 'run-id', status: 'PASSED', evidence_hash: hash, created_at: Date.now(), evidence_json: '{"fixtures":[]}'}];
    if (url.pathname.endsWith('/shadow')) body = [];
    if (url.pathname.endsWith('/promote')) {promotion = route.request().postDataJSON(); body = {};}
    return route.fulfill({contentType: 'application/json', body: JSON.stringify(body)});
  });
  await page.goto('https://watchtower.example/');
  await page.setContent(`<style>body{margin:0;font:16px Arial;color:#1b1b1f;--wt-surface:#f8f9ff;--wt-border:#727780} md-dialog{--md-dialog-container-color:var(--wt-surface)} button,select,input{font:inherit}</style><button data-rule-candidates-open>Test improvements</button>${fragment}`);
  for (const stylesheet of ['tokens.css', 'md-theme.css', 'components.css', 'assistant.css'])
    await page.addStyleTag({path: path.join(resources, 'static/styles', stylesheet)});
  await page.addScriptTag({path: path.join(resources, 'static/scripts/material-web-bundle.js')});
  await page.evaluate(() => {const dialog = document.querySelector('[data-rule-candidates-dialog]'); dialog.quick = true; Object.assign(dialog.dataset, {ruleId: '42', csrfHeader: 'X-CSRF-TOKEN', csrfToken: 'fixture'});});
  await page.addScriptTag({path: path.join(resources, 'static/scripts/rule-candidates.js')});
  await page.getByRole('button', {name: 'Test improvements', exact: true}).click();
  await expect(page.locator('[data-candidate-availability]')).toContainText('not sandboxed');
  await page.locator('[data-candidate-list] button').click();
  await expect(page.locator('[data-candidate-definition]')).toContainText(next);
  await expect(page.locator('[data-candidate-definition] img')).toHaveCount(0);
  await expect(page.locator('[data-candidate-results]')).toContainText('PASSED');
  const box = await page.getByRole('dialog').boundingBox();
  expect(box.x).toBeGreaterThanOrEqual(0);expect(box.x + box.width).toBeLessThanOrEqual(testInfo.project.use.viewport.width + 1);
  const sizes = await page.locator('[data-rule-candidates-dialog]').evaluate(element => {
    const scroller = element.shadowRoot.querySelector('.scroller');
    return {width: scroller.clientWidth, content: scroller.scrollWidth};
  });
  expect(sizes.content).toBeLessThanOrEqual(sizes.width + 1);
  await page.locator('[data-rule-candidates-dialog]').evaluate(element => element.shadowRoot.querySelector('.scroller').scrollTop = 0);
  await page.screenshot({path: testInfo.outputPath('rule-candidates.png')});
  await page.locator('[data-candidate-action="promote"]').click();
  await expect(page.locator('[data-candidate-status]')).toContainText('approval box');expect(promotion).toBeUndefined();
  await page.locator('[data-candidate-rationale]').fill('Reviewed held-out and sampled behavior');
  await page.locator('[data-candidate-approval]').check();
  await page.locator('[data-candidate-action="promote"]').click();
  await expect.poll(() => promotion).toEqual({version: 2, revision: next, runId: 'run-id', evidenceHash: hash, rationale: 'Reviewed held-out and sampled behavior'});
  await page.getByRole('button', {name: 'Close AI assistant'}).click();
  await expect(page.getByRole('button', {name: 'Test improvements', exact: true})).toBeFocused();
});

test('drawer survives navigation, safely renders answers and supports history/cancellation', async ({page}, testInfo) => {
  const requested = [];
  await page.route('https://watchtower.example/**', route => {
    const url = new URL(route.request().url());
    requested.push(url.pathname);
    let body = {};
    if (url.pathname === '/') return route.fulfill({contentType: 'text/html', body: '<body></body>'});
    if (url.pathname === '/assistant/status') body = {ready: true, problem: null, message: 'Chat is ready.'};
    if (url.pathname === '/assistant/models') body = {models: [{id: 'fixture-model', efforts: ['low', 'none']}], defaultModel: 'fixture-model', defaultEffort: 'low'};
    if (url.pathname === '/assistant/active') body = [];
    if (url.pathname === '/assistant/turn' && route.request().method() === 'POST') body = {sessionId: 's1', turnId: 't1'};
    if (url.pathname.replace(/\/events$/, '') === '/assistant/turn/t1') body = {status: 'COMPLETED', answer: '<img src=x onerror=alert(1)> [unsafe](javascript:alert) [rule](/rule/edit/regex/1)\n\nRule 1 uses a recorded revision. The example is illustrative.', activity: [{tool: 'get_rule', status: 'read'}], expiresAt: Date.now() + 86400000};
    if (url.pathname === '/assistant/history') body = [{session_id: 's1', started_at: Date.now(), model: 'fixture-model'}];
    if (url.pathname === '/assistant/history/s1') body = {session: {model: 'fixture-model', effort: 'low', expires_at: Date.now() + 86400000}, messages: [{role: 'user', text: 'Explain a rule'}, {role: 'assistant', text: 'Saved evidence'}], turns: [{turn_id: 't2', status: 'RUNNING'}]};
    if (url.pathname === '/assistant/turn/t2') body = {status: 'RECOVERING', activity: [], expiresAt: Date.now() + 86400000};
    if (url.pathname === '/assistant/turn/t2/cancel') body = {status: 'CANCELED'};
    // t1 progress arrives over a real SSE body; t2's refused stream exercises the polling fallback.
    if (url.pathname === '/assistant/turn/t1/events') return route.fulfill({contentType: 'text/event-stream', body: 'event: turn\ndata: ' + JSON.stringify(body) + '\n\n'});
    return route.fulfill({contentType: 'application/json', body: JSON.stringify(body)});
  });
  await page.goto('https://watchtower.example/');
  await page.setContent(`<style>body{margin:0;font:16px Arial;color:#1b1b1f;--wt-surface:#f8f9ff;--wt-border:#727780} .wt-shell{display:grid;grid-template-columns:80px 1fr} nav{background:#e4e8f1;height:100vh} md-dialog{--md-dialog-container-color:var(--wt-surface)} button,select,input{font:inherit} textarea{box-sizing:border-box} main{padding:24px}</style>
    <div class="wt-shell"><nav><button data-assistant-open aria-label="Open assistant">Chat</button></nav>${drawer}<main id="content">Rules</main></div>`);
  await page.addStyleTag({path: path.join(resources, 'static/styles/assistant.css')});
  await page.addScriptTag({path: path.join(resources, 'static/scripts/material-web-bundle.js')});
  await page.addScriptTag({path: path.join(resources, 'static/scripts/assistant.js')});
  await page.evaluate(() => Object.assign(document.querySelector('wt-assistant-drawer').dataset, {csrfHeader: 'X-CSRF-TOKEN', csrfToken: 'fixture'}));
  await page.getByRole('button', {name: 'Open assistant'}).click();
  await expect(page.locator('[data-assistant-model]')).toHaveValue('fixture-model');
  await expect(page.locator('[data-assistant-model-label]')).toHaveText('fixture-model · low');
  await page.getByLabel('Message', {exact: true}).fill('Explain a rule');
  await page.getByRole('button', {name: 'Send', exact: true}).click();
  await expect(page.locator('[data-assistant-status]')).toContainText('get rule (read)');
  await expect(page.locator('[data-assistant-messages] img')).toHaveCount(0);
  await expect(page.locator('[data-assistant-messages] a')).toHaveAttribute('href', '/rule/edit/regex/1');
  expect(requested).toContain('/assistant/turn/t1/events');
  expect(requested).not.toContain('/assistant/turn/t1');
  await page.evaluate(() => document.querySelector('#content').textContent = 'Another report after navigation');
  await expect(page.locator('[data-assistant-messages]')).toContainText('illustrative');
  // A side panel on the right edge, not a centred modal: the page beside it stays visible.
  const panel = page.getByRole('complementary', {name: 'AI assistant'});
  const box = await panel.boundingBox();
  if (testInfo.project.use.viewport.width >= 1024) expect(box.x).toBeGreaterThan(testInfo.project.use.viewport.width / 2);
  else expect(box.x).toBeGreaterThanOrEqual(0);
  expect(box.x + box.width).toBeLessThanOrEqual(testInfo.project.use.viewport.width + 1);
  await expect(page.locator('#content')).toBeVisible();
  await page.screenshot({path: testInfo.outputPath('assistant.png')});
  await page.getByRole('button', {name: 'History', exact: true}).click();
  await page.locator('[data-assistant-history-list] button').first().click();
  await expect(page.locator('[data-assistant-status]')).toContainText('Working');
  expect(requested).toContain('/assistant/turn/t2');
  await expect(page.locator('[data-assistant-messages]')).toContainText('Saved evidence');
  await page.getByRole('button', {name: 'Stop answer'}).click();
  await expect(page.locator('[data-assistant-status]')).toContainText('Stopped');
  await page.getByRole('button', {name: 'Close AI assistant'}).click();
  await expect(page.getByRole('button', {name: 'Open assistant'})).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByLabel('Message', {exact: true})).toBeFocused();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('button', {name: 'Open assistant'})).toBeFocused();
});

test('reviewed missed-case dialog saves pinned references and fits the viewport', async ({page}, testInfo) => {
  const fragment = fs.readFileSync(path.join(resources, 'templates/fragments/missedcase.html'), 'utf8');
  const commit = 'a'.repeat(40);
  let saved;
  await page.route('https://watchtower.example/**', route => {
    if (route.request().url() === 'https://watchtower.example/') return route.fulfill({contentType: 'text/html', body: '<body></body>'});
    if (route.request().method() === 'POST') { saved = route.request().postDataJSON(); return route.fulfill({contentType: 'application/json', body: '{"id":"reviewed-case"}'}); }
    return route.fulfill({contentType: 'application/json', body: JSON.stringify(saved ? [{evidence_type: 'PENTEST', cwe: 'CWE-79', affected_path: 'app/source.py', first_line: 3, commit_hash: commit, fixture_ref: 'fixtures/positive-v1.py', reviewer: 'alice'}] : [])});
  });
  await page.goto('https://watchtower.example/');
  await page.setContent(`<style>body{margin:0;font:16px Arial;color:#1b1b1f;--wt-surface:#f8f9ff;--wt-border:#727780} md-dialog{--md-dialog-container-color:var(--wt-surface);max-width:min(560px,96vw)} button,select,input{font:inherit}</style><button data-missed-open>Record missed vulnerability</button>${fragment}`);
  await page.addStyleTag({path: path.join(resources, 'static/styles/tokens.css')});
  await page.addStyleTag({path: path.join(resources, 'static/styles/md-theme.css')});
  await page.addStyleTag({path: path.join(resources, 'static/styles/components.css')});
  await page.addScriptTag({path: path.join(resources, 'static/scripts/material-web-bundle.js')});
  await page.evaluate(() => { const dialog = document.querySelector('[data-missed-dialog]'); dialog.quick = true; Object.assign(dialog.dataset, {repoId: '42', csrfHeader: 'X-CSRF-TOKEN', csrfToken: 'fixture'}); });
  await page.addScriptTag({path: path.join(resources, 'static/scripts/missed-case.js')});
  await page.getByRole('button', {name: 'Record missed vulnerability', exact: true}).click();
  const values = {commit, affectedPath: 'app/source.py', firstLine: '3', evidenceRef: 'pentest/report-42', cwe: 'CWE-79', fixtureRef: 'fixtures/positive-v1.py', fixtureHash: 'b'.repeat(64), language: 'python'};
  for (const [key, value] of Object.entries(values)) await page.locator(`[data-missed-field="${key}"]`).locator('input').fill(value);
  await page.locator('[data-missed-field="evidenceType"]').selectOption('PENTEST');
  const box = await page.getByRole('dialog').boundingBox();
  expect(box.x).toBeGreaterThanOrEqual(0); expect(box.x + box.width).toBeLessThanOrEqual(testInfo.project.use.viewport.width + 1);
  await page.evaluate(async () => { await Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {}))); });
  await page.locator('[data-missed-dialog]').evaluate(element => element.shadowRoot.querySelector('.scroller').scrollTop = 0);
  await page.screenshot({path: testInfo.outputPath('missed-case.png')});
  await page.getByRole('button', {name: 'Save confirmed case'}).click();
  await expect(page.locator('[data-missed-status]')).toContainText('Confirmed case saved');
  expect(saved.repositoryId).toBe(42); expect(saved.commit).toBe(commit); expect(saved.ruleId).toBeNull();
  await expect(page.locator('[data-missed-list]')).toContainText('reviewed by alice');
  await page.getByRole('button', {name: 'Close AI assistant'}).click();
  await expect(page.getByRole('button', {name: 'Record missed vulnerability', exact: true})).toBeFocused();
});

test('rule review report dialog fits the viewport and keeps the wide matrix scrollable', async ({page}, testInfo) => {
  const template = fs.readFileSync(path.join(resources, 'templates/rules/rule-edit.html'), 'utf8');
  const dialogMarkup = template.match(/<md-dialog data-rule-report-dialog[\s\S]*?<\/md-dialog>/)[0];
  const languages = ['any', 'dependencies', 'iac', 'java', 'javascript', 'json/yaml', 'python'];
  const rows = Array.from({length: 25}, (_, i) => ({cwe: 'CWE-' + (i + 1), rank: i + 1, name: 'Top 25 weakness ' + (i + 1),
    cells: i % 3 ? {} : {java: {rules: 3, ran_30d: 2}, python: {rules: 1, ran_30d: 0}}}));
  rows.push({cwe: 'Unclassified', rank: null, name: 'Rules without a CWE', cells: {any: {rules: 4, ran_30d: 4}}});
  const body = {settings: {enabled: true, weekday: 1, version: 0}, report: {id: 'r1', period: '2026-W42', trigger: 'SCHEDULED', actor: 'system', created_at: Date.now(),
    summary: {counts: {rules: 40, attention: 2, insufficient_data: 9}, attention_truncated: false,
      attention: [{rule_id: 1, name: 'Noisy SQL string concatenation', module: 'PMD', owner: 'appsec', open_reviews: 0, reasons: [{code: 'CONFIRMED_NOISE', reviewed_sample: 9, false_positives: 7}, {code: 'REVIEW_OVERDUE', review_by: '2026-09-01'}]},
        {rule_id: 2, name: 'Hard-coded token', module: 'Regex', owner: null, open_reviews: 1, reasons: [{code: 'NO_OWNER'}, {code: 'NO_CWE'}]}],
      matrix: {cwe_edition: '2024', note: 'A rule in a cell is not proof of comprehensive coverage.', languages, rows}}}};
  await page.route('https://watchtower.example/**', route => {
    if (route.request().url() === 'https://watchtower.example/') return route.fulfill({contentType: 'text/html', body: '<body></body>'});
    return route.fulfill({contentType: 'application/json', body: JSON.stringify(body)});
  });
  await page.goto('https://watchtower.example/');
  await page.setContent(`<style>body{margin:0;font:16px Arial;color:#1b1b1f;--wt-surface:#f8f9ff;--wt-border:#727780} md-dialog{--md-dialog-container-color:var(--wt-surface);max-width:min(720px,96vw)} button,select,input{font:inherit}</style><md-outlined-button data-rule-report-open>Review report</md-outlined-button>${dialogMarkup}`);
  await page.addStyleTag({path: path.join(resources, 'static/styles/tokens.css')});
  await page.addStyleTag({path: path.join(resources, 'static/styles/md-theme.css')});
  await page.addStyleTag({path: path.join(resources, 'static/styles/components.css')});
  await page.addScriptTag({path: path.join(resources, 'static/scripts/material-web-bundle.js')});
  await page.evaluate(() => { const dialog = document.querySelector('[data-rule-report-dialog]'); dialog.quick = true; Object.assign(dialog.dataset, {csrfHeader: 'X-CSRF-TOKEN', csrfToken: 'fixture', canModify: 'true'}); });
  await page.addScriptTag({path: path.join(resources, 'static/scripts/rule-review-report.js')});
  await page.getByText('Review report', {exact: true}).click();
  await expect(page.locator('[data-rule-report-status]')).toContainText('weekly 2026-W42');
  await expect(page.locator('[data-rule-report-matrix] tbody tr')).toHaveCount(26);
  await expect(page.locator('[data-rule-report-matrix] tr.is-gap')).toHaveCount(16);
  const box = await page.getByRole('dialog').boundingBox();
  const width = testInfo.project.use.viewport.width;
  expect(box.x).toBeGreaterThanOrEqual(0); expect(box.x + box.width).toBeLessThanOrEqual(width + 1);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  const matrix = await page.locator('[data-rule-report-matrix]').evaluate(el => ({client: el.clientWidth, scroll: el.scrollWidth, overflow: getComputedStyle(el).overflowX}));
  expect(matrix.overflow).toBe('auto');
  if (width < 600) expect(matrix.scroll).toBeGreaterThan(matrix.client);
  await page.evaluate(async () => { await Promise.all(document.getAnimations().map(animation => animation.finished.catch(() => {}))); });
  await page.screenshot({path: testInfo.outputPath('rule-review-report.png')});
});

test('find similar code dialog explains each step and fits the viewport', async ({page}, testInfo) => {
  const fragment = fs.readFileSync(path.join(resources, 'templates/fragments/missedcase.html'), 'utf8');
  const markup = fragment.match(/<md-dialog th:fragment="variant"[\s\S]*?<\/md-dialog>/)[0];
  const caseId = '0f0e0d0c-0b0a-4900-8000-000000000001', searchId = '11111111-2222-4333-8444-555555555555';
  await page.route('https://watchtower.example/**', route => {
    const url = new URL(route.request().url());
    if (url.pathname === '/') return route.fulfill({contentType: 'text/html', body: '<body></body>'});
    let body = [];
    if (url.pathname === '/repository/evidence/variants/repositories') body = [{id: 1, name: 'billing-service', default_branch: 'main'}, {id: 2, name: 'inventory-service-with-a-long-name', default_branch: 'release/2026.1'}];
    if (url.pathname === '/repository/evidence/variants/case/' + caseId) body = [{id: searchId}];
    if (url.pathname === '/repository/evidence/variants/' + searchId) body = {id: searchId, status: 'DONE', total_matches: 2, rule_id: 42, requested_by: 'steward',
      repositories: [{repository: 'billing-service', commit: 'c'.repeat(40), status: 'COMPLETE', matches: 2, locations: [{path: 'src/main/java/com/example/billing/persistence/InvoiceDao.java', line: 88}, {path: 'src/main/java/com/example/billing/Report.java', line: 12}]}]};
    if (url.pathname.endsWith('/proposal')) body = {status: 'READY', explanation: 'Compared both commits. The vulnerable version should be flagged and the fixed version should not.', line: 3, recorded_line_changed: true,
      excerpt: [1, 2, 3, 4, 5].map(n => ({line: n, text: n === 3 ? '    return "SELECT * FROM orders WHERE id = " + id;' : '    // context line ' + n, changed: n === 3, recorded: n === 3})),
      fixtures: [{expected: 'MATCH', reference: 'missed/' + caseId + '/vulnerable-OrderDao.java', sha256: 'a'.repeat(64), commit: 'a'.repeat(40)}]};
    return route.fulfill({contentType: 'application/json', body: JSON.stringify(body)});
  });
  await page.goto('https://watchtower.example/');
  await page.setContent(`<style>body{margin:0;font:16px Arial;color:#1b1b1f;--wt-surface:#f8f9ff;--wt-border:#727780} md-dialog{--md-dialog-container-color:var(--wt-surface);max-width:min(720px,96vw)}</style><button data-variant-open="${caseId}" data-case-summary="CWE-89 in src/OrderDao.java:3" data-rule-id="42">Find similar code</button>${markup}`);
  for (const sheet of ['tokens.css', 'md-theme.css', 'components.css']) await page.addStyleTag({path: path.join(resources, 'static/styles/' + sheet)});
  await page.addScriptTag({path: path.join(resources, 'static/scripts/material-web-bundle.js')});
  await page.evaluate(() => { const d = document.querySelector('[data-variant-dialog]'); d.quick = true; Object.assign(d.dataset, {csrfHeader: 'X-CSRF-TOKEN', csrfToken: 'fixture'}); });
  await page.addScriptTag({path: path.join(resources, 'static/scripts/variant-search.js')});
  await page.getByRole('button', {name: 'Find similar code'}).click();
  await expect(page.locator('[data-variant-searches]')).toContainText('2 places to review');
  await page.getByText('Compare commits', {exact: true}).click();
  await expect(page.locator('[data-variant-proposal]')).toContainText('part of the fix');
  const width = testInfo.project.use.viewport.width;
  const box = await page.getByRole('dialog').boundingBox();
  expect(box.x).toBeGreaterThanOrEqual(0); expect(box.x + box.width).toBeLessThanOrEqual(width + 1);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  await page.evaluate(async () => { await Promise.all(document.getAnimations().map(a => a.finished.catch(() => {}))); });
  await page.screenshot({path: testInfo.outputPath('find-similar-code.png')});
});

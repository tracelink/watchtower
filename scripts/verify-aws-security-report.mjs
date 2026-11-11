// Runs against the real Thymeleaf fixture emitted by ScanReportExporterTest. No server or database.
import { chromium } from '../watchtower-core/src/main/frontend/material-web/node_modules/playwright/index.mjs';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir } from 'node:os';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';

const fixture = process.argv[2];
if (!fixture) throw new Error('Pass the AWS_UI_FIXTURE path from the focused test log');
const staticRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../watchtower-core/src/main/resources/static');
const output = path.dirname(fixture);
const bootstrap = execFileSync('unzip', ['-p', path.join(homedir(), '.m2/repository/org/webjars/bootstrap/5.3.3/bootstrap-5.3.3.jar'), 'META-INF/resources/webjars/bootstrap/5.3.3/css/bootstrap.min.css']);
const styles = '<link rel="stylesheet" href="/bootstrap.css">' + ['icons', 'tokens', 'md-theme', 'base', 'components', 'layout'].map(n => `<link rel="stylesheet" href="/static/styles/${n}.css">`).join('');
let html = (await readFile(fixture, 'utf8')).replace('</head>', `${styles}<style>body{padding:24px;max-width:1500px;margin:auto}</style></head>`);
html = html.replace('</body>', '<script type="module" src="/static/scripts/material-web-bundle.js"></script><script src="/static/scripts/finding-workspace.js"></script></body>');
const browser = await chromium.launch({ headless: true, channel: 'chrome' });
const errors = [];
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  await context.route('**/*', async route => {
    const url = new URL(route.request().url());
    if (url.origin !== 'http://watchtower.test') return route.abort();
    if (url.pathname === '/fonts/Inter-latin-variable.woff2') return route.fulfill({ contentType: 'font/woff2', body: await readFile(path.join(staticRoot, 'fonts/Inter-latin-variable.woff2')) });
    if (url.pathname === '/webjars/material-design-icons/3.0.1/MaterialIcons-Regular.woff2') return route.fulfill({ contentType: 'font/woff2', body: execFileSync('unzip', ['-p', path.join(homedir(), '.m2/repository/org/webjars/material-design-icons/3.0.1/material-design-icons-3.0.1.jar'), 'META-INF/resources/webjars/material-design-icons/3.0.1/MaterialIcons-Regular.woff2']) });
    if (url.pathname === '/bootstrap.css') return route.fulfill({ contentType: 'text/css', body: bootstrap });
    if (url.pathname === '/report') return route.fulfill({ contentType: 'text/html', body: html });
    if (url.pathname.startsWith('/static/')) {
      const file = path.resolve(staticRoot, url.pathname.slice('/static/'.length));
      if (!file.startsWith(staticRoot + path.sep)) return route.abort();
      return route.fulfill({ contentType: file.endsWith('.css') ? 'text/css' : 'text/javascript', body: await readFile(file) });
    }
    if (url.pathname.endsWith('/source')) return route.fulfill({ json: {
      file: 'src/one.java', commit: 'a'.repeat(40), startLine: 1, requestedEndLine: 3,
      lines: ['<script>globalThis.sourceExecuted = true</script>', 'safe display fixture', 'third line'], truncated: false,
    } });
    if (url.pathname.includes('/aws/findings/')) {
      const unknown = url.pathname.endsWith('b'.repeat(64));
      return route.fulfill({ json: {
        nativeSeverity: unknown ? 'UNKNOWN' : 'CRITICAL', confidence: 'HIGH', validationStatus: 'NOT_VALIDATED',
        riskType: unknown ? 'UNKNOWN' : 'SQL_INJECTION', findingId: unknown ? 'other' : 'finding', jobId: 'job',
        sensitive: unknown, sourceLocations: unknown ? [] : [0, 1],
        sensitivityReason: unknown ? 'Unknown risk type; source suppressed' : 'Reviewed type and exact uploaded paths',
        providerUrl: 'https://review.example.com', omissions: ['Provider reasoning omitted by source-free retention policy'],
        locations: [{ file: 'src/one.java', startLine: 1, endLine: 3 }, { file: 'src/two.java', startLine: 8, endLine: 9 }],
      } });
    }
    return route.abort();
  });
  const page = await context.newPage(); page.on('pageerror', error => errors.push(error.message));
  await page.goto('http://watchtower.test/report');
  await page.getByRole('button', { name: 'View pinned source' }).first().waitFor();
  assert.equal(await page.getByRole('button', { name: 'View pinned source' }).count(), 2);
  await page.getByRole('button', { name: 'View pinned source' }).first().click();
  await page.getByText('safe display fixture', { exact: false }).waitFor();
  assert.equal(await page.evaluate(() => globalThis.sourceExecuted), undefined);
  assert.match(await page.locator('[data-provider-detail]').innerText(), /NOT_VALIDATED/);
  assert.equal(await page.getByRole('link', { name: 'Open AWS evidence (AWS authorization required)' }).getAttribute('rel'), 'noopener noreferrer');
  await page.evaluate(() => document.fonts.ready);
  assert.equal(await page.locator('[data-finding-workspace]').count(), 1);
  await page.screenshot({ path: path.join(output, 'desktop.png'), fullPage: true });
  await page.locator('[data-finding-severity]').evaluate(element => { element.value = 'UNKNOWN'; element.dispatchEvent(new Event('change', { bubbles: true })); });
  await page.getByText('Unknown risk type; source suppressed', { exact: true }).waitFor();
  assert.equal(await page.getByRole('button', { name: 'View pinned source' }).count(), 0);
  assert.equal(await page.locator('[data-finding-item]:visible').count(), 1);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: path.join(output, 'mobile.png'), fullPage: true });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
  assert.deepEqual(errors, []);
  console.log(JSON.stringify({ passed: true, screenshots: [path.join(output, 'desktop.png'), path.join(output, 'mobile.png')] }));
} finally { await browser.close(); }

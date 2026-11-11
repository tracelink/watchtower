const {expect} = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

const authenticatedRoutes = [
  '/',
  '/scan/dashboard',
  '/scan',
  '/scan/results',
  '/scan/mcr',
  '/uploadscan/dashboard',
  '/uploadscan',
  '/uploadscan/results',
  '/imagescan/dashboard',
  '/imagescan/results',
  '/reposcan/dashboard',
  '/reposcan',
  '/rulesets',
  '/designer',
  '/rule/edit',
  '/repository/pull_request',
  '/repository/container',
  '/apisettings',
  '/prsettings',
  '/logging',
  '/encryption',
  '/usermgmt',
  '/rolemgmt',
  '/admin/ui/components',
  '/profile'
  // Pages of one record (a report, a repository such as /repository/pull_request/1) come from
  // WATCHTOWER_E2E_REPORT_PATHS, since their ids depend on the database
].concat((process.env.WATCHTOWER_E2E_REPORT_PATHS || '').split(',')
  .map(path => path.trim()).filter(path => path.startsWith('/')));

function credentialsAvailable() {
  return Boolean(process.env.WATCHTOWER_E2E_USERNAME && process.env.WATCHTOWER_E2E_PASSWORD);
}

async function login(page) {
  await page.goto('/login');
  await page.locator('form#login_form').waitFor();
  // The Material field, not [name=...] alone: Playwright pierces shadow DOM, and the field's own
  // inner <input> carries the same name, so the bare selector matched two elements.
  await page.locator('md-outlined-text-field[name="username"]').evaluate((field, value) => {
    field.value = value;
    field.dispatchEvent(new Event('input', {bubbles: true}));
    field.dispatchEvent(new Event('change', {bubbles: true}));
  }, process.env.WATCHTOWER_E2E_USERNAME);
  await page.locator('md-outlined-text-field[name="password"]').evaluate((field, value) => {
    field.value = value;
    field.dispatchEvent(new Event('input', {bubbles: true}));
    field.dispatchEvent(new Event('change', {bubbles: true}));
  }, process.env.WATCHTOWER_E2E_PASSWORD);
  await Promise.all([
    page.waitForURL(url => !url.pathname.endsWith('/login')),
    page.getByRole('button', {name: /^login$/i}).click()
  ]);
}

async function assertNoSeriousAxeViolations(page) {
  const result = await new AxeBuilder({page}).withTags(['wcag2a', 'wcag2aa', 'wcag22aa']).analyze();
  expect(result.violations, JSON.stringify(result.violations, null, 2)).toEqual([]);
}

async function assertPageContract(page) {
  await expect(page.locator('main')).toBeVisible();
  await expect(page.locator('h1')).toHaveCount(1);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow, 'page-level horizontal overflow').toBeLessThanOrEqual(1);
  const versionPosition = await page.locator('.watchtower-version-badge').evaluateAll(elements =>
    elements.map(element => getComputedStyle(element).position));
  expect(versionPosition, 'the version label must remain in document flow')
    .not.toContain('fixed');
  const tables = page.locator('table:visible');
  for (let index = 0; index < await tables.count(); index += 1) {
    await expect(tables.nth(index).locator('caption')).toHaveCount(1);
  }
}

async function installPerformanceObservers(page) {
  await page.addInitScript(() => {
    window.__watchtowerVitals = {cls: 0, lcp: 0};
    new PerformanceObserver(list => {
      const entries = list.getEntries();
      window.__watchtowerVitals.lcp = entries.at(-1)?.startTime || 0;
    }).observe({type: 'largest-contentful-paint', buffered: true});
    new PerformanceObserver(list => {
      for (const entry of list.getEntries()) {
        if (!entry.hadRecentInput) window.__watchtowerVitals.cls += entry.value;
      }
    }).observe({type: 'layout-shift', buffered: true});
  });
}

async function assertPerformanceGates(page) {
  const vitals = await page.evaluate(() => window.__watchtowerVitals);
  expect(vitals.lcp, 'LCP must remain below 2.5 seconds').toBeLessThan(2500);
  expect(vitals.cls, 'CLS must remain below 0.1').toBeLessThan(0.1);
}

module.exports = {
  assertNoSeriousAxeViolations,
  assertPageContract,
  assertPerformanceGates,
  authenticatedRoutes,
  credentialsAvailable,
  installPerformanceObservers,
  login
};

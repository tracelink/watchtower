const {test, expect} = require('@playwright/test');
const {
  assertNoSeriousAxeViolations,
  assertPageContract,
  assertPerformanceGates,
  authenticatedRoutes,
  credentialsAvailable,
  installPerformanceObservers,
  login
} = require('./support');

test.describe('authenticated route contract', () => {
  test.skip(!credentialsAvailable(), 'Set WATCHTOWER_E2E_USERNAME and WATCHTOWER_E2E_PASSWORD.');

  test.beforeEach(async ({page}) => login(page));

  for (const route of authenticatedRoutes) {
    test(`${route} has stable semantics and no serious accessibility violations`, async ({page}) => {
      const consoleErrors = [];
      const failedSameOrigin = [];
      page.on('console', message => {
        if (message.type() === 'error') consoleErrors.push(message.text());
      });
      page.on('requestfailed', request => {
        if (new URL(request.url()).origin === new URL(page.url()).origin) failedSameOrigin.push(request.url());
      });

      await installPerformanceObservers(page);
      const response = await page.goto(route);
      expect(response?.status(), `HTTP status for ${route}`).toBeLessThan(400);
      await assertPageContract(page);
      await assertNoSeriousAxeViolations(page);
      await assertPerformanceGates(page);

      if (!route.endsWith('/dashboard') && route !== '/') {
        const chartRequests = await page.evaluate(() => performance.getEntriesByType('resource')
          .map(entry => entry.name.toLowerCase()).filter(name => name.includes('chart.js')));
        expect(chartRequests, `Chart.js loaded on ${route}`).toEqual([]);
      }
      expect(failedSameOrigin, `failed assets on ${route}`).toEqual([]);
      expect(consoleErrors, `console errors on ${route}`).toEqual([]);
    });
  }
});

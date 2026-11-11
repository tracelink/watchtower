const {test, expect} = require('@playwright/test');
const {credentialsAvailable, login} = require('./support');

test.describe('UI refinement release blockers', () => {
  test.skip(!credentialsAvailable(), 'Set WATCHTOWER_E2E_USERNAME and WATCHTOWER_E2E_PASSWORD.');
  test.beforeEach(async ({page}) => login(page));

  test('persistent shell omits the content header and keeps browser titles synchronized', async ({page}) => {
    await page.goto('/scan/results/all');
    const heading = (await page.locator('#content h1.page-title').textContent()).trim();
    await expect(page.locator('.wt-sidebar-account [data-sidebar-username]')).toHaveCount(1);
    await expect(page.locator('.main-content > .main-navbar')).toHaveCount(0);
    await expect(page).toHaveTitle(`${heading} · Watchtower`);

    const nextLink = page.locator('a.wt-pagination__step', {hasText: 'Next'});
    if (await nextLink.count()) {
      await nextLink.click();
      await expect(page).toHaveTitle(`${heading} · Watchtower`);
      const localizedValues = await page.locator('.localizetime').allTextContents();
      expect(localizedValues.some(value => /^\d{10,}$/.test(value.trim())), localizedValues.join(', '))
        .toBe(false);
    }
  });

  test('results default to all scans and expose route-aware navigation', async ({page}) => {
    for (const route of ['/scan/results', '/uploadscan/results', '/imagescan/results']) {
      await page.goto(route);
      await expect(page).toHaveURL(new RegExp(`${route}/all(?:\\?|$)`));
      await expect(page.locator('[aria-current="page"]', {hasText: 'All Scans'})).toBeVisible();
      await expect(page.locator('.wt-breadcrumb a')).not.toHaveCount(0);
      await expect(page.locator('.wt-breadcrumb [aria-current="page"]')).toHaveCount(1);
    }
    const entityLinks = page.locator('a.wt-entity-link');
    if (await entityLinks.count()) await expect(entityLinks.first()).toBeVisible();
  });

  test('dashboard range controls and overflowing rankings expose their affordances', async ({page}) => {
    await page.goto('/scan/dashboard');
    await expect(page.locator('md-outlined-select#dashboard-period')).toBeVisible();
    await expect(page.locator('#dashboard-period md-select-option[value="custom"]')).toHaveCount(1);
    await expect(page.locator('[data-custom-range-for="dashboard-period"]')).toHaveCount(0);
    const metricTabs = page.locator('[data-dashboard-tabs] [role="tab"]');
    await expect(metricTabs.first()).toHaveAttribute('aria-selected', 'true');
    if (await metricTabs.count() > 1) {
      await metricTabs.nth(1).click();
      await expect(page.locator('#dashboard-performance-view')).toBeVisible();
      // The chart lives in the Performance tab, so check it while that tab is open. Without data
      // the dashboard shows its "no data" message in place of the canvas instead.
      if (await page.locator('#performance-trend').count()) {
        await expect(page.locator('#performance-trend:visible, #performance-no-data:visible'))
          .toHaveCount(1);
      }
      await metricTabs.first().click();
      await expect(page.locator('#dashboard-activity-view')).toBeVisible();
    }
    const ranking = page.locator('[data-dashboard-distribution]');
    await expect(ranking).toHaveAttribute('tabindex', '0');
    const overflows = await ranking.evaluate(element => element.scrollHeight > element.clientHeight + 1);
    if (overflows) await expect(page.locator('[data-dashboard-scroll-hint]')).toBeVisible();
    const recentRows = page.locator('.wt-recent-scans tbody tr');
    if (await recentRows.count()) {
      await expect(recentRows.first().locator('.wt-scan-target')).toBeVisible();
      await expect(recentRows.first().locator('.wt-severity-counts')).toBeVisible();
    }
  });

  test('rule designer does not show an empty state beside configured designers', async ({page}) => {
    await page.goto('/designer');
    await expect(page.locator('.wt-designer-page')).toBeVisible();
    if (await page.locator('[aria-label="Rule designer modules"] [role="tab"]').count()) {
      await expect(page.getByText('No rule designers configured.', {exact: true})).toHaveCount(0);
      await expect(page.locator('[data-rule-designer]')).toBeVisible();
    }
  });

  test('scan submission shows scanner state on one line and the five newest scans', async ({page}) => {
    await page.goto('/scan');
    await expect(page.locator('.wt-page-bar .wt-status-chip').first()).toBeVisible();
    await expect(page.locator('form[data-scan-submission]')).toBeVisible();
    expect(await page.locator('[data-recent-scan-row]').count()).toBeLessThanOrEqual(5);
    await expect(page.locator('[data-recent-scan-list] a[href="/scan/results/all"]')).toBeVisible();
  });

  test('rulesets keep actions with the picker and paginate material-filtered rules', async ({page}) => {
    await page.goto('/rulesets');
    await expect(page.locator('[data-ruleset-picker] .wt-ruleset-actions')).toBeVisible();
    await expect(page.locator('md-outlined-select[data-rule-filter]')).toHaveCount(2);
    const options = page.locator('#rulesetselect md-select-option');
    if (await options.count()) {
      await expect(page.getByText('No rulesets are available. Create or import one to begin.',
        {exact: true})).toHaveCount(0);
    }
    for (const scope of await page.locator('[data-rule-scope]').all()) {
      const rows = scope.locator('[data-rule-row]');
      if (await rows.count()) {
        await expect(scope.locator('[data-rule-row]:visible')).toHaveCount(
          Math.min(10, await rows.count()));
      }
    }
  });

  for (const [route, rowSelector, emptyText] of [
    ['/usermgmt', 'tbody tr', 'No users registered'],
    ['/apisettings', 'tbody tr', 'No API integrations configured'],
    ['/repository/pull_request', '[data-repository-row]', 'No repository integrations are configured.']
  ]) {
    test(`${route} never shows an empty state beside populated data`, async ({page}) => {
      await page.goto(route);
      if (await page.locator(rowSelector).count()) {
        await expect(page.getByText(emptyText, {exact: true})).toHaveCount(0);
      }
    });
  }

  test('code repository selects one integration and pages the results region', async ({page}) => {
    await page.goto('/repository/pull_request');
    const rows = page.locator('[data-repository-row]');
    if (await rows.count()) {
      expect(await rows.count()).toBeLessThanOrEqual(10);
      await expect(page.locator('[data-repository-tab]').first())
        .toHaveAttribute('aria-selected', 'true');
      // One integration's repositories at a time, server-paged (no client-side panels).
      await expect(page.locator('#results-region table')).toHaveCount(1);
      expect(await page.locator('[data-repository-row]:visible').count()).toBeGreaterThan(0);

      const next = page.locator('#results-region .wt-pagination__step', {hasText: 'Next'});
      if (await next.getAttribute('href')) {
        await next.click();
        await expect(page).toHaveURL(/\?page=1$/);
        await expect(page.locator('#results-region')).toBeVisible();
        await expect(page.locator('[data-repository-tab]').first())
          .toHaveAttribute('aria-selected', 'true');
      }
    }
  });

  test('configured reports keep bounded findings and accessible links', async ({page}) => {
    const paths = (process.env.WATCHTOWER_E2E_REPORT_PATHS || '').split(',')
      .map(value => value.trim()).filter(Boolean);
    test.skip(!paths.length, 'Set WATCHTOWER_E2E_REPORT_PATHS to deployed PR/MCR report routes.');
    for (const reportPath of paths) {
      await page.goto(reportPath);
      const workspace = page.locator('[data-finding-workspace]');
      if (await workspace.count()) {
        const itemCount = await workspace.locator('[data-finding-item]').count();
        if (itemCount) {
          await expect(workspace.locator('[data-finding-item]:visible')).toHaveCount(
            Math.min(10, itemCount));
          await expect(workspace.locator('[data-finding-range]')).toBeVisible();
          await expect(workspace.locator('md-outlined-text-field[data-finding-search]')).toBeVisible();
          await expect(workspace.locator('md-outlined-select[data-finding-severity]')).toBeVisible();
          const widths = await workspace.locator('[data-split-workspace]').evaluate(element => {
            const list = element.querySelector('.wt-finding-list').getBoundingClientRect();
            const detail = element.querySelector('.wt-finding-detail').getBoundingClientRect();
            return {list: list.width, detail: detail.width, sideBySide: detail.left > list.left};
          });
          // Below 992px the list sits above the detail, full width; the split only exists beside.
          if (widths.sideBySide) {
            expect(widths.list).toBeLessThan(widths.detail);
            await expect(workspace.locator('.wt-finding-detail')).toHaveCSS('overflow-y', 'hidden');
          }
        }
        await expect(page.locator('.wt-breadcrumb [aria-current="page"]')).toHaveCount(1);
        // PR and MCR reports open with one line (docs/design-system.md, "Restraint").
        await expect(page.locator('.wt-report-bar')).toBeVisible();
        await expect(page.locator('#content .card')).toHaveCount(0);
      }
    }
  });
});

const {test, expect} = require('@playwright/test');
const {assertNoSeriousAxeViolations} = require('./support');

test('login is lightweight, semantic, and accessible', async ({page}) => {
  const failedSameOrigin = [];
  const loadedAssets = [];
  page.on('requestfailed', request => {
    if (new URL(request.url()).origin === new URL(page.url()).origin) failedSameOrigin.push(request.url());
  });
  page.on('request', request => loadedAssets.push(request.url().toLowerCase()));

  await page.goto('/login');
  await expect(page.locator('main')).toBeVisible();
  await expect(page.getByRole('heading', {level: 1})).toHaveCount(1);
  await expect(page.locator('md-outlined-text-field[name="username"]'))
    .toHaveAttribute('autocomplete', 'username');
  await expect(page.locator('md-outlined-text-field[name="password"]'))
    .toHaveAttribute('autocomplete', 'current-password');

  const forbidden = ['chart.js', 'jquery', 'datatables', 'luxon', 'codemirror'];
  for (const fragment of forbidden) {
    expect(loadedAssets.some(url => url.includes(fragment)), `${fragment} loaded on login`).toBe(false);
  }
  expect(failedSameOrigin).toEqual([]);
  await assertNoSeriousAxeViolations(page);
});

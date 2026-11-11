const {test, expect} = require('@playwright/test');
const {assertPageContract, credentialsAvailable, login} = require('./support');

test.describe('375px graceful degradation', () => {
  test.skip(!credentialsAvailable(), 'Set WATCHTOWER_E2E_USERNAME and WATCHTOWER_E2E_PASSWORD.');

  test.beforeEach(async ({page}) => login(page));

  for (const route of ['/', '/scan/dashboard', '/uploadscan/dashboard', '/imagescan/dashboard',
    '/scan', '/scan/results', '/uploadscan', '/imagescan/results', '/rule/edit', '/profile',
    '/logging', '/rolemgmt', '/reposcan/dashboard', '/reposcan', '/repository/pull_request']) {
    test(`${route} remains usable without page overflow`, async ({page}) => {
      await page.goto(route);
      await assertPageContract(page);
      const controls = page.locator('button:visible, a:visible, input:visible, select:visible, md-filled-button:visible, md-outlined-button:visible');
      expect(await controls.count(), `${route} has an essential interactive control`).toBeGreaterThan(0);
    });
  }
});

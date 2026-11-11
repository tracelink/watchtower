const {test, expect} = require('@playwright/test');
const {credentialsAvailable, login} = require('./support');

test.describe('reviewed visual baselines', () => {
  test.skip(process.env.WATCHTOWER_VISUAL_BASELINES !== '1',
    'Set WATCHTOWER_VISUAL_BASELINES=1 after reviewed baselines are captured.');

  for (const theme of ['light', 'dark']) {
    test(`login ${theme}`, async ({page}) => {
      await page.addInitScript(value => localStorage.setItem('theme', value), theme);
      await page.goto('/login');
      await expect(page).toHaveScreenshot(`login-${theme}.png`, {fullPage: true});
    });

    test(`home ${theme}`, async ({page}) => {
      test.skip(!credentialsAvailable(), 'Authenticated visual checks need E2E credentials.');
      await page.addInitScript(value => localStorage.setItem('theme', value), theme);
      await login(page);
      await page.goto('/');
      await expect(page).toHaveScreenshot(`home-${theme}.png`, {fullPage: true});
    });

    for (const [name, route] of [['pr-dashboard', '/scan/dashboard'],
      ['rules', '/rule/edit'], ['profile', '/profile']]) {
      test(`${name} ${theme}`, async ({page}) => {
        test.skip(!credentialsAvailable(), 'Authenticated visual checks need E2E credentials.');
        await page.addInitScript(value => localStorage.setItem('theme', value), theme);
        await login(page);
        await page.goto(route);
        await expect(page).toHaveScreenshot(`${name}-${theme}.png`, {fullPage: true});
      });
    }
  }
});

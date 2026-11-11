const {defineConfig} = require('@playwright/test');

const baseURL = process.env.WATCHTOWER_E2E_BASE_URL || 'http://127.0.0.1:7777';

module.exports = defineConfig({
  testDir: './e2e',
  outputDir: 'test-results/playwright',
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [
    ['line'],
    ['html', {outputFolder: 'playwright-report', open: 'never'}],
    ['junit', {outputFile: 'test-results/playwright/results.xml'}]
  ],
  expect: {
    timeout: 10_000,
    toHaveScreenshot: {maxDiffPixels: 5, animations: 'disabled'}
  },
  use: {
    baseURL,
    actionTimeout: 10_000,
    navigationTimeout: 30_000,
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    reducedMotion: 'reduce'
  },
  projects: [
    {name: 'desktop', testIgnore: /mobile\.spec\.js/, use: {viewport: {width: 1440, height: 900}}},
    {name: 'tablet', testIgnore: /mobile\.spec\.js/, use: {viewport: {width: 768, height: 1024}}},
    {name: 'mobile-smoke', testMatch: /mobile\.spec\.js/, use: {viewport: {width: 375, height: 812}}}
  ]
});

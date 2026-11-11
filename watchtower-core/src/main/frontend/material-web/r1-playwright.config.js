const {defineConfig} = require('@playwright/test');
module.exports = defineConfig({
  testDir: '.', testMatch: 'r1-browser.spec.js', workers: 1, reporter: 'line',
  outputDir: 'test-results/r1-browser',
  use: {browserName: 'chromium', channel: 'chrome', headless: true, reducedMotion: 'reduce', screenshot: 'only-on-failure'},
  projects: [
    {name: 'desktop', use: {viewport: {width: 1280, height: 900}}},
    {name: 'mobile', use: {viewport: {width: 375, height: 812}}}
  ]
});

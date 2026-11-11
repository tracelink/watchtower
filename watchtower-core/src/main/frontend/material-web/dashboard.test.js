const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/dashboard/dashboard-insights.js'), 'utf8');
const switcherScript = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/dashboard/dashboard-stats-switcher.js'), 'utf8');
const dashboardTemplate = fs.readFileSync(path.resolve(__dirname,
  '../../resources/templates/fragments/dashboard.html'), 'utf8');
const rangeButtons = Array.from(new JSDOM(dashboardTemplate).window.document.querySelectorAll(
  '[data-dashboard-range-options] [data-period]'), button => button.dataset.period);
assert.deepEqual(rangeButtons, ['last-week', 'last-thirty-days', 'last-six-months', 'all-time', 'custom'],
  'the approved range buttons are all shown');
const dom = new JSDOM(`<!doctype html><body>
  <div data-dashboard-tabs role="tablist">
    <button role="tab" aria-selected="true" aria-controls="dashboard-activity-view">Activity</button>
    <button role="tab" aria-selected="false" tabindex="-1" aria-controls="dashboard-performance-view">Performance</button>
  </div>
  <div id="dashboard-activity-view" role="tabpanel"></div>
  <div id="dashboard-performance-view" role="tabpanel" hidden></div>
  <select id="dashboard-period"><option value="last-thirty-days" selected>30 days</option><option value="custom">Custom</option></select>
  <div data-chart-region><canvas id="scans-trend"></canvas><p id="scans-no-data"></p></div>
  <div data-chart-region><canvas id="findings-trend"></canvas><p id="findings-no-data"></p></div>
  <div data-chart-region><canvas id="performance-trend"></canvas><p id="performance-no-data"></p></div>
  <span data-dashboard-total="scans"></span>
  <span data-dashboard-total="findings"></span>
  <span data-dashboard-total="performance"></span>
  <span data-dashboard-ranked-total></span>
  <ol data-dashboard-distribution></ol>
  <button data-dashboard-show-all aria-expanded="false" hidden><span class="material-icons">expand_more</span><span data-dashboard-show-all-label>All rules</span></button>
  <p id="distribution-no-data"></p>
</body>`, {runScripts: 'dangerously'});

dom.window.matchMedia = () => ({matches: true});
dom.window.requestAnimationFrame = callback => callback();
dom.window.HTMLCanvasElement.prototype.getContext = () => ({});
dom.window.toggleChart = () => {};
dom.window.wtSetChartLoading = () => {};
dom.window.wtThemeValue = (_name, fallback) => fallback;
dom.window.getColors = count => Array.from({length: count}, (_value, index) =>
  `rgb(${index}, 0, 0)`);
dom.window.Chart = class {
  constructor(_context, config) { this.config = config; }
  destroy() {}
};
dom.window.eval(script);
dom.window.eval(switcherScript);

const metricTabs = dom.window.document.querySelectorAll('[data-dashboard-tabs] [role="tab"]');
metricTabs[1].click();
assert.equal(metricTabs[1].getAttribute('aria-selected'), 'true');
assert.equal(dom.window.document.getElementById('dashboard-activity-view').hidden, true);
assert.equal(dom.window.document.getElementById('dashboard-performance-view').hidden, false);

const insights = new dom.window.WatchtowerDashboardInsights('dashboard-period', 'pull_request');
const distribution = dom.window.document.querySelector('[data-dashboard-distribution]');
const ruleNames = ['CommentRequired', 'Betterleaks: private-key', 'A', 'B', 'C', 'D', 'E'];
insights.renderDistribution({
  labels: ruleNames,
  names: ['CommentRequired', 'private-key', 'A', 'B', 'C', 'D', 'E'],
  scanners: [{name: 'PMD', icon: 'coffee'}, {name: 'Betterleaks', icon: 'key'}, null, null, null, null, null],
  counts: [65, 5, 4, 3, 2, 1, 1]
});
const rows = dom.window.document.querySelectorAll('[data-dashboard-distribution] li');
assert.equal(rows.length, 7);
assert.equal(rows[0].querySelector('strong').textContent, 'CommentRequired');
assert.equal(rows[1].querySelector('strong').textContent, 'private-key',
  'the scanner prefix moves into the tile instead of the rule name');
assert.equal(rows[0].querySelector('.wt-distribution-scanner').dataset.tip, 'PMD rule');
// A named tile needs a role: a bare span may not carry aria-label.
assert.equal(rows[0].querySelector('.wt-distribution-scanner').getAttribute('role'), 'img');
assert.equal(rows[0].querySelector('.wt-distribution-scanner .material-icons').textContent, 'coffee');
assert.equal(rows[2].querySelector('.wt-distribution-scanner').dataset.tip,
  "A · scanner unknown (its module isn't installed)", 'an unknown rule says so rather than guessing a scanner');
assert.equal(rows[2].querySelector('.wt-distribution-scanner .material-icons').textContent, 'help');
assert.ok(!rows[2].querySelector('.wt-distribution-scanner').classList.contains('wt-scanner-tile--ran'),
  'an unknown scanner keeps the grey tile');
assert.equal(rows[0].querySelector('[data-distribution-bar]').style.getPropertyValue('--wt-bar-size'), '100%',
  'bars compare each rule with the top rule');
assert.equal(dom.window.document.querySelector('[data-dashboard-ranked-total]').textContent, '81 findings');
const showAll = dom.window.document.querySelector('[data-dashboard-show-all]');
assert.equal(showAll.hidden, false);
assert.equal(showAll.querySelector('[data-dashboard-show-all-label]').textContent, 'All 7 rules');
assert.equal(rows[6].hidden, true, 'only the top six rules show until "All 7 rules" is pressed');
showAll.click();
assert.equal(rows[6].hidden, false);
assert.equal(showAll.getAttribute('aria-expanded'), 'true');

insights.period = 'last-thirty-days';
const chart = insights.renderTrend('scans-trend', 'scans-no-data', 'Scans completed', {
  labels: ['Monday', 'Tuesday'], counts: [2, 4]
});
assert.equal(chart.config.type, 'bar', 'a 30-day range is read day by day as bars');
assert.equal(chart.config.data.datasets.length, 1);
assert.equal(chart.config.data.datasets[0].label, 'Scans completed');
assert.equal(chart.config.data.datasets[0].tension, 0);
assert.equal(chart.config.options.animation, false);
assert.equal('yAxisID' in chart.config.data.datasets[0], false);
assert.equal(dom.window.document.querySelector('[data-dashboard-total="scans"]').textContent,
  '6 total · busiest Tuesday (4)');

insights.period = 'all-time';
const trend = insights.renderTrend('findings-trend', 'findings-no-data', 'Findings found', {
  labels: ['Monday', 'Tuesday'], counts: [1, 3]
});
assert.equal(trend.config.type, 'line', 'All time is read as a trend line');
assert.equal(trend.config.data.datasets[0].tension, 0, 'straight segments, no curves between points');
insights.renderAverage({counts: [2, 4]}, {counts: [1, 3]});
assert.equal(dom.window.document.querySelector('[data-dashboard-total="findings"]').textContent,
  '4 total · avg 0.7 per scan');

insights.period = 'last-thirty-days';
const performanceChart = insights.renderPerformanceTrend({
  labels: ['Monday', 'Tuesday'], samples: [2, 3], totalMs: [1200, 1500],
  sourceMs: [200, 300], scannersMs: [800, 900], processingMs: [200, 300],
  scannerSeries: [{name: 'PMDScanner', values: [600, 700]},
    {name: 'EsLintScanner', values: [200, 200]}]
});
assert.equal(performanceChart.config.type, 'bar');
assert.deepEqual(Array.from(performanceChart.config.data.datasets, dataset => dataset.label),
  ['Source', 'Processing', 'PMD', 'ESLint'],
  'each step is one stacked part; aggregate scanner time is replaced by scanner-level parts');
assert.equal(performanceChart.config.data.datasets[0].data[0], 0.2,
  'performance milliseconds should render as readable seconds');
assert.equal(performanceChart.config.options.scales.y.stacked, true);
assert.equal(performanceChart.config.options.plugins.tooltip.callbacks.footer([{dataIndex: 1}]),
  'Average scan: 1.5 s');
assert.equal(dom.window.document.querySelector('[data-dashboard-total="performance"]').textContent,
  '5 scans averaged');

insights.period = 'last-six-months';
const performanceTrend = insights.renderPerformanceTrend({
  labels: ['Apr', 'May'], samples: [2, 3], totalMs: [1200, 1500],
  sourceMs: [200, 300], processingMs: [200, 300],
  scannerSeries: [{name: 'PMDScanner', values: [600, 700]}]
});
assert.equal(performanceTrend.config.type, 'line', 'long ranges read Speed as a trend');
assert.deepEqual(Array.from(performanceTrend.config.data.datasets, dataset => dataset.label),
  ['Source', 'Processing', 'PMD', 'Total']);
assert.deepEqual(Array.from(performanceTrend.config.data.datasets[3].borderDash), [5, 4],
  'the total is the dashed line');
assert.equal(performanceTrend.config.options.scales.y.stacked, false);

insights.period = 'all-time';
const repositoryDuration = insights.renderDurationTrend({
  labels: ['Sep 2026', 'Oct 2026'], samples: [2, 3], totalMs: [1200, 2100]
});
assert.equal(repositoryDuration.config.type, 'line');
assert.deepEqual(Array.from(repositoryDuration.config.data.datasets[0].data), [1.2, 2.1]);
assert.equal(repositoryDuration.config.data.datasets.length, 1,
  'repository speed shows elapsed scan time without invented PR phases');
assert.equal(dom.window.document.querySelector('[data-dashboard-total="performance"]').textContent,
  '5 scans averaged');
insights.period = 'custom';
const dailyDuration = insights.renderDurationTrend({
  labels: ['2026-10-20', '2026-10-21'], samples: [1, 1], totalMs: [1000, 1500]
});
assert.equal(dailyDuration.config.type, 'bar');

// Custom range panel: Custom opens it, a quick range fills From/To, Apply selects it and labels the button.
const doc = dom.window.document;
const rangeHost = doc.createElement('div');
rangeHost.innerHTML = `<div data-dashboard-range-options>
    <button data-period="all-time" aria-pressed="true">All time</button>
    <button data-period="custom" aria-pressed="false" aria-expanded="false"><span data-custom-label>Custom</span></button></div>
  <div data-range-picker hidden><button data-quick="7">Last 7 days</button>
    <button data-quick="6-months">Last 6 months</button>
    <fieldset id="dashboard-period-custom-range"><input id="dashboard-period-custom-from"><input id="dashboard-period-custom-to">
    <div role="alert" hidden></div><button data-range-cancel>Cancel</button><button data-range-apply>Apply</button></fieldset></div>`;
doc.body.append(rangeHost);
const changes = [];
doc.getElementById('dashboard-period').addEventListener('change', () => changes.push(doc.getElementById('dashboard-period').value));
const pickerInsights = new dom.window.WatchtowerDashboardInsights('dashboard-period', 'pull_request');
pickerInsights.refresh = () => {};
pickerInsights.initialize();
const customButton = doc.querySelector('[data-period="custom"]');
const picker = doc.querySelector('[data-range-picker]');
customButton.click();
assert.equal(picker.hidden, false, 'Custom opens the panel without changing the range');
assert.equal(changes.length, 0);
doc.querySelector('[data-quick="7"]').click();
const fromValue = doc.getElementById('dashboard-period-custom-from').value;
const toValue = doc.getElementById('dashboard-period-custom-to').value;
assert.equal((new Date(toValue) - new Date(fromValue)) / 86400000, 6, 'Last 7 days covers seven calendar days');
doc.querySelector('[data-quick="6-months"]').click();
const sixMonthStart = new Date();
sixMonthStart.setMonth(sixMonthStart.getMonth() - 5, 1);
assert.equal(doc.getElementById('dashboard-period-custom-from').value,
  [sixMonthStart.getFullYear(), String(sixMonthStart.getMonth() + 1).padStart(2, '0'), '01'].join('-'));
doc.getElementById('dashboard-period-custom-from').value = '2026-10-20';
doc.getElementById('dashboard-period-custom-to').value = '2026-10-10';
doc.querySelector('[data-range-apply]').click();
assert.equal(picker.hidden, false, 'an inverted range stays open with an error');
assert.equal(picker.querySelector('[role="alert"]').hidden, false);
doc.getElementById('dashboard-period-custom-from').value = '2026-07-18';
doc.getElementById('dashboard-period-custom-to').value = '2026-10-16';
doc.querySelector('[data-range-apply]').click();
assert.equal(picker.hidden, true);
assert.deepEqual(changes, ['custom']);
assert.equal(customButton.getAttribute('aria-pressed'), 'true');
assert.match(customButton.querySelector('[data-custom-label]').textContent, /(18.*Jul|Jul.*18).*(16.*Oct|Oct.*16)/, 'the button shows the chosen range in the browser date format');

// All time leaves out scans with impossible dates (e.g. 1989) and says so in an amber chip.
(async () => {
  const allTime = new JSDOM(`<!doctype html><body>
    <input type="hidden" id="dashboard-period" value="all-time">
    <span data-dashboard-impossible-dates hidden><span data-dashboard-impossible-label></span></span>
    <canvas id="scans-trend"></canvas><p id="scans-no-data"></p>
    <canvas id="findings-trend"></canvas><p id="findings-no-data"></p>
    <span data-dashboard-total="scans"></span><span data-dashboard-total="findings"></span>
    <ol data-dashboard-distribution></ol><p id="distribution-no-data"></p>
  </body>`, {runScripts: 'dangerously'});
  const win = allTime.window;
  win.matchMedia = () => ({matches: true});
  win.HTMLCanvasElement.prototype.getContext = () => ({});
  win.toggleChart = () => {};
  win.wtSetChartLoading = () => {};
  win.wtThemeValue = (_name, fallback) => fallback;
  win.Chart = class { constructor(_context, config) { this.config = config; } destroy() {} };
  win.wtMetricQuery = (_id, period) => 'period=' + period;
  win.wtFetchMetric = async url => (url.includes('scans-by-period')
    ? {labels: ['Sep 2026', 'Oct'], counts: [2, 3], impossibleDates: 1, impossibleBefore: '2015-01-01'}
    : {labels: ['Sep 2026', 'Oct'], counts: [1, 1]});
  win.eval(script);
  const allTimeInsights = new win.WatchtowerDashboardInsights('dashboard-period', 'pull_request');
  await allTimeInsights.refresh();
  const chip = win.document.querySelector('[data-dashboard-impossible-dates]');
  assert.equal(chip.hidden, false);
  assert.equal(chip.textContent, '1 scan with an impossible date left out');
  assert.match(chip.dataset.tip, /dated before 2015/);
  assert.equal(allTimeInsights.charts['scans-trend'].config.type, 'line', 'All time is a monthly line');
  win.wtFetchMetric = async () => ({labels: ['Sep 2026'], counts: [1]});
  await allTimeInsights.refresh();
  assert.equal(chip.hidden, true, 'the chip hides when every date is real');
  console.log('Dashboard insights jsdom test passed');
})().catch(error => { console.error(error); process.exit(1); });

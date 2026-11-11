const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const resources = path.resolve(__dirname, '../../resources');
const read = relative => fs.readFileSync(path.join(resources, relative), 'utf8');
const components = read('static/styles/components.css');
const layout = read('static/styles/layout.css');
const dashboard = read('templates/fragments/dashboard.html');
const performance = read('templates/fragments/prscanperformance.html');
const prReport = read('templates/pull_requests/scanreport.html');
const mcrReport = read('templates/pull_requests/mcrreport.html');
const pagination = read('templates/fragments/pagination.html');
const resultTemplates = [
  read('templates/pull_requests/results.html'),
  read('templates/pull_requests/mcrs.html'),
  read('templates/upload_scan/results.html'),
  read('templates/image_scan/results.html')
].join('\n');

const versionRule = components.match(/\.watchtower-version-badge\s*\{[^}]*\}/s)?.[0] || '';
assert.equal(versionRule.includes('position: fixed'), false,
  'the version must remain in document flow and never cover content');

const tableRule = components.match(/\.wt-table-scroll\s*>\s*table\s*\{[^}]*\}/s)?.[0] || '';
assert.equal(tableRule.includes('min-inline-size: 42rem'), false,
  'ordinary tables must not be forced wider than the viewport');
assert.match(components, /\.wt-table-scroll--wide\s*>\s*table/,
  'only explicitly dense tables should opt into a minimum width');

assert.match(components, /grid-template-columns:\s*minmax\(18rem, var\(--wt-split-percent, 34%\)\) 0\.75rem minmax\(20rem, 1fr\)/,
  'desktop findings should expose a bounded resizable split');
assert.match(components, /\.wt-workspace-resizer[^}]+cursor:\s*col-resize/s,
  'resizable workspaces need a recognizable pointer target');
assert.match(components, /\.wt-workspace-grid\s*\{[^}]*block-size:\s*var\(--wt-findings-workspace-height\)/s,
  'report findings should use one stable desktop workspace height');
assert.match(components, /\.wt-finding-list-viewport\s*\{[^}]*overflow-y:\s*auto/s,
  'the paged finding list should scroll inside the bounded workspace');
assert.match(components, /\.wt-finding-detail\s*\{[^}]*block-size:\s*100%[^}]*overflow-y:\s*auto/s,
	'long finding details and opened source scroll inside the pane instead of being cut off (user, 2026-10-22)');
assert.match(components, /\.wt-page-step\s*\{[^}]*min-block-size:\s*2rem/s,
  'finding page controls should retain compact accessible targets');
assert.match(components + layout, /@media\s*\(prefers-reduced-motion:\s*reduce\)/,
  'all optional motion needs an explicit reduced-motion fallback');

// docs/design-system.md "Restraint": the MCR report opens with one line, like the PR report.
assert.equal(mcrReport.includes('class="card'), false,
  'the MCR report has no cards above its findings');
assert.match(mcrReport, /class="wt-mini-chip wt-meta-chip wt-report-head__status/,
  'the review status is a chip by the title, like the PR report');
assert.match(mcrReport, /<md-dialog id="mcrStatusDialog"[\s\S]*data-mcr-status/,
  'the review status form is in a dialog');
// docs/design-system.md "Restraint": the PR report starts with one line, not cards.
assert.equal(prReport.includes('class="card'), false,
  'the PR report has no cards above its findings');
// UAT walkthrough 2026-10-15: that line is now a row of icon chips (author, integration, time...).
assert.match(prReport, /class="wt-meta-chips/,
  'the PR report shows what was scanned on one line');
assert.equal((prReport.match(/data-wt-dialog-target="#bypassDialog"/g) || []).length, 1,
  'bypassing is one button that opens one dialog');
assert.equal((prReport.match(/<md-dialog/g) || []).length, 1,
  'every bypass state lives in the one dialog');
assert.equal(performance.includes('wt-info-trigger'), false,
  'performance explanations must not use overflow-producing pseudo tooltips');
assert.equal(performance.includes('<table'), false,
  'performance details should reflow as metrics instead of a wide table');
assert.equal(/font-weight:\s*(700|800|900|bold)/.test(components), false,
  'routine UI typography must stay within the approved 400/500/600 weights');
assert.equal(resultTemplates.includes('btn-success'), false,
  'report navigation actions must be neutral rather than semantic green');
assert.equal(pagination.includes('btn btn-secondary'), false,
  'shared pagination should not inherit large filled Bootstrap capsules');
assert.match(components, /\.wt-pagination__page\s*\{[^}]*inline-size:\s*2\.25rem[^}]*block-size:\s*2\.25rem/s,
  'numbered page controls should use compact square targets');
assert.match(components, /\.wt-pagination__step:focus-visible/,
  'previous and next controls need a visible keyboard focus state');

assert.match(dashboard, /data-dashboard-insights/);
assert.match(dashboard, /id="scans-trend"/);
assert.match(dashboard, /id="findings-trend"/);
assert.match(dashboard, /data-dashboard-distribution/);
assert.equal((dashboard.match(/data-dashboard-chart-frame/g) || []).length, 2,
  'trend charts and ranked findings should share the same frame hook');
assert.match(components, /\.wt-dashboard-grid\s*\{[^}]*--wt-dashboard-frame-height:/s,
  'the dashboard should define one shared desktop chart-frame height');
assert.match(components, /\.wt-distribution-list\s*\{[^}]*overflow-y:\s*auto/s,
  'long ranked findings should scroll without stretching adjacent charts');
assert.equal(dashboard.includes('violations-pie'), false);
assert.equal(dashboard.includes('scans-vios-line'), false);

console.log('UI consistency contract passed');

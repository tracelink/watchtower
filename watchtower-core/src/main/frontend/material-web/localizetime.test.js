const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

// UAT #9: script-built and server-rendered times share one format that always names the zone.
const dom = new JSDOM(`<body><span class="localizetime">1760500000000</span>
  <span class="localizetime" data-millis="1760500000000">15 Oct 2025, 03:46</span>
  <span class="localizetime">2025-10-15T03:46:40Z</span><span class="localizetime">not a time</span></body>`, {runScripts: 'dangerously'});
const w = dom.window;
w.eval(fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/localizetime.js'), 'utf8'));
w.document.dispatchEvent(new w.Event('DOMContentLoaded'));
const formatted = w.WatchtowerTime.format(1760500000000);
assert.match(formatted, /2025/);
assert.match(formatted, /(UTC|GMT|[A-Z]{2,5})/, 'the zone is always named');
const spans = w.document.querySelectorAll('.localizetime');
[0, 1, 2].forEach(i => assert.equal(spans[i].textContent, formatted));
assert.equal(spans[3].textContent, 'not a time', 'unparseable text is left as it is');
assert.match(spans[0].title, /^2025-10-15T03:46:40\.000Z/);
console.log('Local time: shared formatter names the zone and matches server-rendered times');

// Lists show a short time ("09 Aug 2024, 01:46"); the full time with its zone is the hover text.
{
  const shortDom = new JSDOM(`<body><span class="localizetime" data-time-style="short">1723148172000</span>
    <span class="localizetime" data-time-style="short">0</span></body>`, {runScripts: 'dangerously'});
  const sw = shortDom.window;
  sw.eval(fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/localizetime.js'), 'utf8'));
  sw.document.dispatchEvent(new sw.Event('DOMContentLoaded'));
  const [short, never] = sw.document.querySelectorAll('.localizetime');
  const full = sw.WatchtowerTime.format(1723148172000);
  assert.notEqual(short.textContent, full, 'the list shows the short form');
  assert.doesNotMatch(short.textContent, /(UTC|GMT)/, 'the short form leaves the zone to the hover text');
  assert.doesNotMatch(short.textContent, /:\d\d:\d\d/, 'no seconds in the short form');
  assert.equal(short.dataset.tip, full, 'hovering shows the full time with its zone');
  assert.equal(short.getAttribute('aria-label'), full);
  assert.equal(short.tabIndex, 0, 'the hover text is reachable by keyboard');
  assert.equal(never.textContent, 'Not completed');
  assert.match(short.textContent, /2024/, 'an earlier year is kept');
  const thisYear = new Date(new Date().getFullYear(), 0, 15, 10, 30).getTime();
  assert.doesNotMatch(sw.WatchtowerTime.short(thisYear), new RegExp(String(new Date().getFullYear())),
    'this year reads "15 Jan, 10:30" (Fixes board): the year is only on hover');
  console.log('Local time: short list times keep the full time on hover');
}

// Users: last login is relative ("42 min ago"), with the full time (and a stale note) on hover.
{
  const now = Date.now();
  const relDom = new JSDOM(`<body><span class="localizetime" data-time-style="relative">${now - 42 * 60000}</span>
    <span class="localizetime" data-time-style="relative" data-stale-note="No login for over 90 days">${now - 520 * 24 * 3600000}</span></body>`,
    {runScripts: 'dangerously'});
  const rw = relDom.window;
  rw.eval(fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/localizetime.js'), 'utf8'));
  rw.document.dispatchEvent(new rw.Event('DOMContentLoaded'));
  const [recent, stale] = rw.document.querySelectorAll('.localizetime');
  assert.match(recent.textContent, /42 minutes ago/);
  assert.equal(recent.dataset.tip, rw.WatchtowerTime.format(now - 42 * 60000));
  assert.match(stale.textContent, /17 months ago/);
  assert.match(stale.dataset.tip, /No login for over 90 days$/);
  assert.equal(stale.tabIndex, 0);
  const day = 24 * 3600000;
  assert.match(rw.WatchtowerTime.relative(now - 8 * day, now), /8 days ago/);
  assert.match(rw.WatchtowerTime.relative(now - 45 * day, now), /6 weeks ago/);
  assert.equal(rw.WatchtowerTime.relative(now - 5000, now), 'just now');
  console.log('Local time: relative times keep the full time on hover');
}

// Profile "Since" chip: the date alone, the full time on hover.
{
  const dateDom = new JSDOM(`<body><span class="localizetime" data-time-style="date">1787740688000</span></body>`, {runScripts: 'dangerously'});
  const dw = dateDom.window;
  dw.eval(fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/localizetime.js'), 'utf8'));
  dw.document.dispatchEvent(new dw.Event('DOMContentLoaded'));
  const [since] = dw.document.querySelectorAll('.localizetime');
  assert.match(since.textContent, /2026/);
  assert.doesNotMatch(since.textContent, /\d\d:\d\d/, 'no time of day in the date form');
  assert.equal(since.dataset.tip, dw.WatchtowerTime.format(1787740688000));
  console.log('Local time: date-only chips keep the full time on hover');
}

// Integrations: a chip's hover text ends in the check time, in the viewer's zone, added once.
{
  const tipDom = new JSDOM(`<body><span data-tip="Last check passed: " data-tip-millis="1760500000000">Connected</span>
    <span data-tip="No check yet" data-tip-millis="">Not checked</span></body>`, {runScripts: 'dangerously'});
  const tw = tipDom.window;
  tw.eval(fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/localizetime.js'), 'utf8'));
  tw.document.dispatchEvent(new tw.Event('DOMContentLoaded'));
  tw.WatchtowerTime.localize(tw.document);
  const [checked, unchecked] = tw.document.querySelectorAll('span');
  assert.equal(checked.dataset.tip, 'Last check passed: ' + tw.WatchtowerTime.format(1760500000000));
  assert.equal(unchecked.dataset.tip, 'No check yet', 'no time, no change');
  console.log('Local time: chip hover text ends in the localized check time');
}

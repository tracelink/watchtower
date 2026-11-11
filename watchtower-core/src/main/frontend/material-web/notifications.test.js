const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/auto-dismiss-alerts.js'), 'utf8');
const dom = new JSDOM(`<!doctype html><body>
  <div id="success" class="alert alert-success alert-dismissible"></div>
  <div id="error" class="alert alert-danger alert-dismissible"></div>
</body>`, {runScripts: 'dangerously'});

const timers = [];
const closed = [];
dom.window.setTimeout = callback => { timers.push(callback); return timers.length; };
dom.window.clearTimeout = () => {};
dom.window.bootstrap = {Alert: {getOrCreateInstance: element => ({close: () => closed.push(element.id)})}};
dom.window.eval(script);
dom.window.document.dispatchEvent(new dom.window.Event('DOMContentLoaded'));

assert.equal(timers.length, 1);
assert.equal(dom.window.document.getElementById('error').dataset.autoDismissReady, undefined);
timers[0]();
assert.deepEqual(closed, ['success']);
assert.equal(script.includes('$('), false);
assert.match(script, /6000/);
assert.match(script, /mouseenter/);
assert.match(script, /focusin/);
console.log('Notification jsdom test passed');

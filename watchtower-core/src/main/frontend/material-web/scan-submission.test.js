const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname,
  '../../resources/static/scripts/scan-submission.js'), 'utf8');
const dom = new JSDOM(`<!doctype html><body>
  <form data-scan-submission>
    <button data-submit-button>Submit</button>
    <span class="wt-submit-status"></span>
  </form>
  <form data-confirm="Continue?"><button>Admin action</button></form>
  <label class="wt-drop-zone" for="uploadControl">
    <span class="wt-drop-zone__title">Drop a ZIP here or choose a file</span>
    <span data-upload-file-chip hidden><span data-upload-file-name></span><button type="button" data-upload-file-clear>x</button></span>
    <input type="file" id="uploadControl" data-upload-file>
  </label>
</body>`, {runScripts: 'dangerously'});

let nativeConfirms = 0;
dom.window.confirm = () => { nativeConfirms++; return false; };
dom.window.eval(script);

const form = dom.window.document.querySelector('[data-scan-submission]');
const firstSubmit = new dom.window.Event('submit', {bubbles: true, cancelable: true});
assert.equal(form.dispatchEvent(firstSubmit), true);
assert.equal(form.dataset.submitting, 'true');
assert.equal(form.querySelector('[data-submit-button]').disabled, true);
assert.equal(form.querySelector('.wt-submit-status').textContent, 'Submitting scan…');

const duplicateSubmit = new dom.window.Event('submit', {bubbles: true, cancelable: true});
assert.equal(form.dispatchEvent(duplicateSubmit), false);

// data-confirm forms are confirmed once, by confirm-action.js; this script must not ask again
// with a native confirm() after the user already confirmed in the dialog.
const adminForm = dom.window.document.querySelector('[data-confirm]');
const confirmedSubmit = new dom.window.Event('submit', {bubbles: true, cancelable: true});
assert.equal(adminForm.dispatchEvent(confirmedSubmit), true);
assert.equal(nativeConfirms, 0);

// The chosen upload shows as a chip in the drop zone instead of the browser's file bar; x clears it.
const doc = dom.window.document;
const upload = doc.getElementById('uploadControl');
const chip = doc.querySelector('[data-upload-file-chip]');
const title = doc.querySelector('.wt-drop-zone__title');
assert.equal(chip.hidden, true);
Object.defineProperty(upload, 'files', {configurable: true, value: [{name: 'release-1.4.zip', size: 18 * 1048576}]});
upload.dispatchEvent(new dom.window.Event('change', {bubbles: true}));
assert.equal(chip.hidden, false);
assert.equal(title.hidden, true);
assert.equal(doc.querySelector('[data-upload-file-name]').textContent, 'release-1.4.zip · 18.0 MB');
Object.defineProperty(upload, 'files', {configurable: true, value: []});
doc.querySelector('[data-upload-file-clear]').click();
assert.equal(chip.hidden, true);
assert.equal(title.hidden, false);

console.log('Scan submission jsdom test passed');

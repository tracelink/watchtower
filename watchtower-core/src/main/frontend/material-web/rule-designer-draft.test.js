const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');

const script = fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/rule-designer.js'), 'utf8');

function page(banner) {
  const dom = new JSDOM(`<!doctype html><body>
    ${banner ? '<div data-draft-banner data-draft-id="5d1c5a0e-0000-4000-8000-000000000001"></div>' : ''}
    <section data-rule-designer>
      <form id="run" action="/designer/regex/query" data-designer-run-form><textarea data-designer-input name="source"></textarea></form>
      <form id="save" action="/designer/regex/save"><input name="name"></form>
      <form id="other" action="/somewhere/else/save"></form>
    </section></body>`, {runScripts: 'dangerously'});
  dom.window.eval(script);
  const submit = id => dom.window.document.getElementById(id).dispatchEvent(new dom.window.Event('submit', {bubbles: true, cancelable: true}));
  const draftField = id => dom.window.document.querySelectorAll(`#${id} input[name="draft"]`);
  return {submit, draftField};
}

// A designer opened from a draft sends the draft's id with the save, and only with the save.
const drafted = page(true);
drafted.submit('save');
assert.equal(drafted.draftField('save').length, 1);
assert.equal(drafted.draftField('save')[0].value, '5d1c5a0e-0000-4000-8000-000000000001');
assert.equal(drafted.draftField('save')[0].type, 'hidden');
drafted.submit('save');
assert.equal(drafted.draftField('save').length, 1, 'a second try does not add it twice');
drafted.submit('run');
drafted.submit('other');
assert.equal(drafted.draftField('run').length, 0, 'running the rule is not saving it');
assert.equal(drafted.draftField('other').length, 0, 'only the designers save forms');

// A plain designer page is left alone.
const plain = page(false);
plain.submit('save');
assert.equal(plain.draftField('save').length, 0);
console.log('rule-designer-draft.test.js passed');

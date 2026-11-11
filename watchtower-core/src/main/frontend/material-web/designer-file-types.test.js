// Rule designers (Regex, JSON): when an admin limited the scanner's file types and the rule's file
// extension falls outside them, a small chip says the rule won't run (design canvas, board ScannerTypes).
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require('jsdom');
const script = fs.readFileSync(path.resolve(__dirname, '../../resources/static/scripts/designer-file-types.js'), 'utf8');

function page(types) {
  const attribute = types === null ? '' : ` data-types="${types}"`;
  const dom = new JSDOM(`<md-outlined-text-field id="ruleFileExtension"></md-outlined-text-field>
    <div data-file-types-notice${attribute} hidden>
      <span data-file-types-chip data-tip=""><span data-file-types-chip-text></span></span>
      <a href="/configuration/modules">File types</a></div>`, {runScripts: 'outside-only'});
  dom.window.eval(script);
  const document = dom.window.document;
  const field = document.getElementById('ruleFileExtension');
  const notice = document.querySelector('[data-file-types-notice]');
  const type = value => {
    field.value = value;
    field.dispatchEvent(new dom.window.Event('input', {bubbles: true}));
  };
  return {notice, type, chip: document.querySelector('[data-file-types-chip]'), text: () => document.querySelector('[data-file-types-chip-text]').textContent};
}

(() => {
  // no limit set on the scanner: never a notice
  let p = page(null);
  p.type('.py');
  assert.equal(p.notice.hidden, true);
  p = page('');
  p.type('.py');
  assert.equal(p.notice.hidden, true);

  // limited scanner: an extension outside the types gets the chip, one inside does not
  p = page('.java,.xml');
  p.type('.py');
  assert.equal(p.notice.hidden, false);
  assert.equal(p.text(), "Won't run on .py");
  assert.match(p.chip.dataset.tip, /\.java, \.xml/);
  p.type('.java');
  assert.equal(p.notice.hidden, true);

  // blank means all files, so the scanner's own limit is the only limit: no notice
  p.type('.py');
  p.type('   ');
  assert.equal(p.notice.hidden, true);

  // a longer extension that still ends with an allowed type can match (a.min.js ends with .js)
  p = page('.js');
  p.type('.min.js');
  assert.equal(p.notice.hidden, true);
  p.type('.min.css');
  assert.equal(p.notice.hidden, false);

  // names: matched as a file name pattern; case is ignored
  p = page('dockerfile*,.yaml');
  p.type('Dockerfile');
  assert.equal(p.notice.hidden, true);
  p.type('.YAML');
  assert.equal(p.notice.hidden, true);
  p.type('.tf');
  assert.equal(p.notice.hidden, false);

  console.log('Designer file types notice: outside-the-types, blank, suffix, name and case checks passed');
})();

(() => {
 'use strict';
 // Rule designers with a file extension (Regex, JSON): when an admin limited the scanner's file types
 // in Scanner modules and this rule's extension falls outside them, the rule would never see a file.
 // A small chip says so. The notice element carries the limit in data-types; it stays hidden when
 // there is no limit or the extension is blank (blank means every file the scanner is given).
 if (window.watchtowerDesignerFileTypesInstalled) return;
 window.watchtowerDesignerFileTypesInstalled = true;

 const glob = (pattern, name) => new RegExp('^' + pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$').test(name);

 // True when some file name could end with the rule's extension and also be of this type.
 function compatible(extension, type) {
  if (type.startsWith('.')) return extension.endsWith(type) || type.endsWith(extension);
  return glob(type, extension);
 }

 function refresh() {
  const notice = document.querySelector('[data-file-types-notice]');
  const field = document.getElementById('ruleFileExtension');
  if (!notice || !field) return;
  const types = (notice.dataset.types || '').split(',').map(type => type.trim().toLowerCase()).filter(Boolean);
  const extension = String(field.value || '').trim().toLowerCase();
  const outside = types.length > 0 && extension !== '' && !types.some(type => compatible(extension, type));
  notice.hidden = !outside;
  if (!outside) return;
  const chip = notice.querySelector('[data-file-types-chip]');
  notice.querySelector('[data-file-types-chip-text]').textContent = `Won't run on ${extension}`;
  chip.dataset.tip = `This scanner is limited to ${types.join(', ')} in Scanner modules, so this rule never sees ${extension} files. Change the file types there, or pick one of those extensions.`;
 }

 document.addEventListener('input', event => {
  if (event.target && event.target.id === 'ruleFileExtension') refresh();
 });
 document.addEventListener('wt-dialog-open', refresh);
 document.addEventListener('click', event => {
  if (event.target.closest('[data-save-rule-open], #saveRuleButton')) setTimeout(refresh, 0);
 });
 refresh();
})();

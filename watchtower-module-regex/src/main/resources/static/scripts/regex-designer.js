(() => {
  const source = document.getElementById('source');
  const openTrigger = document.getElementById('openSaveRegexRuleDialog');
  if (!source || !openTrigger) return;
  const editor = CodeMirror.fromTextArea(source, {lineNumbers: true});
  editor.setSize('100%', null);
  const queryEditor = CodeMirror.fromTextArea(document.getElementById('regexquery'), {lineWrapping: true});
  window.wtDesignerMatches?.(editor);
  const dialog = document.querySelector(openTrigger.dataset.wtDialogTarget);
  openTrigger.addEventListener('click', () => {
    document.getElementById('formSource').value = editor.getValue();
    document.getElementById('ruleQuery').value = queryEditor.getValue();
    dialog.show();
  });
  document.getElementById('cancelSaveRegexRuleDialog').addEventListener('click', () => dialog.close());
})();

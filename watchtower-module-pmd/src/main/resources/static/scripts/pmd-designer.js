(() => {
  const source = document.getElementById('source');
  const openTrigger = document.getElementById('openSavePmdRuleDialog');
  if (!source || !openTrigger) return;
  const editor = CodeMirror.fromTextArea(source, {lineNumbers: true});
  editor.setSize('100%', null);
  const queryEditor = CodeMirror.fromTextArea(document.getElementById('xpathquery'), {lineWrapping: true});
  window.wtDesignerMatches?.(editor);
  const dialog = document.querySelector(openTrigger.dataset.wtDialogTarget);
  openTrigger.addEventListener('click', () => {
    document.getElementById('formSource').value = editor.getValue();
    document.getElementById('ruleQuery').value = queryEditor.getValue();
    document.getElementById('ruleLanguage').value = document.getElementById('queryLanguage').value;
    dialog.show();
  });
  document.getElementById('cancelSavePmdRuleDialog').addEventListener('click', () => dialog.close());
})();

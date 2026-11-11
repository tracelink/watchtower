(() => {
  const source = document.getElementById('code');
  const openTrigger = document.getElementById('openSaveJsonRuleDialog');
  if (!source || !openTrigger) return;
  const editor = CodeMirror.fromTextArea(source, {lineNumbers: true});
  editor.setSize('100%', null);
  const queryEditor = CodeMirror.fromTextArea(document.getElementById('jsonquery'), {lineWrapping: true});
  window.wtDesignerMatches?.(editor);
  const dialog = document.querySelector(openTrigger.dataset.wtDialogTarget);
  openTrigger.addEventListener('click', () => {
    document.getElementById('formSource').value = editor.getValue();
    const format = document.getElementById('jsonSourceFormat').value;
    document.getElementById('formSourceFormat').value = format;
    const extension = document.getElementById('ruleFileExtension');
    if (!extension.value) extension.value = format === 'yaml' ? '.yaml' : '.json';
    document.getElementById('ruleQuery').value = queryEditor.getValue();
    dialog.show();
  });
  document.getElementById('cancelSaveJsonRuleDialog').addEventListener('click', () => dialog.close());
})();

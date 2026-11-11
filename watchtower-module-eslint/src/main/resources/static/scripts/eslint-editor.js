(() => {
  const field = document.getElementById('createFunction');
  if (!field) return;
  const editor = CodeMirror.fromTextArea(field, {lineNumbers: true});
  editor.setSize(null, 260);
})();

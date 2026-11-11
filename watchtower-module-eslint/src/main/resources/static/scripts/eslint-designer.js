(() => {
  const messagesBody = document.querySelector('.messages-tbody');
  if (!messagesBody) return;

  const sourceCodeEditor = CodeMirror.fromTextArea(document.getElementById('sourceCode'), {
    lineNumbers: true, mode: 'javascript'
  });
  sourceCodeEditor.setSize(null, 240);
  const astReader = CodeMirror.fromTextArea(document.getElementById('ast'), {
    lineNumbers: true, mode: 'json', readOnly: true
  });
  astReader.setSize(null, 240);
  const createFunctionEditor = CodeMirror.fromTextArea(document.getElementById('createFunction'), {
    lineNumbers: true, mode: 'javascript'
  });
  createFunctionEditor.setSize(null, 240);
  const createFunctionReader = CodeMirror.fromTextArea(
    document.getElementById('customCreateFunction'), {
      lineNumbers: true, mode: 'javascript', readOnly: true
    });
  createFunctionReader.setSize(null, 240);
  window.wtDesignerMatches?.(sourceCodeEditor);
  // The syntax tree is folded away; the editor measures itself once it is shown.
  document.querySelector('[data-eslint-tree]')?.addEventListener('toggle', () => astReader.refresh());

  // The Messages chip names the message IDs; keep it current as rows are added or removed.
  const messagesLabel = document.querySelector('[data-eslint-messages-label]');
  const updateMessagesLabel = () => {
    if (!messagesLabel) return;
    const keys = Array.from(messagesBody.querySelectorAll('tr'))
      .map(row => row.querySelector('input')?.value.trim())
      .filter(Boolean);
    const count = messagesBody.querySelectorAll('tr').length;
    messagesLabel.textContent = count === 0 ? 'No messages'
      : `${count === 1 ? '1 message' : `${count} messages`}${keys.length ? ': ' + keys.join(', ') : ''}`;
  };
  messagesBody.addEventListener('input', updateMessagesLabel);

  const reindexMessages = () => {
    messagesBody.querySelectorAll('tr').forEach((row, index) => {
      const inputs = row.querySelectorAll('input');
      if (inputs[0]) inputs[0].name = `messages[${index}].key`;
      if (inputs[1]) inputs[1].name = `messages[${index}].value`;
    });
  };

  const createMessageInput = (name, placeholder) => {
    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'form-control';
    input.setAttribute('form', 'run-rule-form');
    input.name = name;
    input.placeholder = placeholder;
    return input;
  };

  const addMessage = () => {
    const index = messagesBody.querySelectorAll('tr').length;
    const row = document.createElement('tr');
    const keyCell = document.createElement('td');
    keyCell.className = 'px-1';
    keyCell.append(createMessageInput(`messages[${index}].key`, 'Message ID'));
    const valueCell = document.createElement('td');
    valueCell.className = 'px-1';
    valueCell.append(createMessageInput(`messages[${index}].value`, 'Message Value'));
    const actionCell = document.createElement('td');
    actionCell.className = 'px-1 text-center';
    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'wt-copy-button wt-icon-danger delete-message';
    remove.setAttribute('aria-label', 'Delete message');
    remove.title = 'Delete message';
    const icon = document.createElement('span');
    icon.className = 'material-icons';
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = 'delete';
    remove.append(icon);
    actionCell.append(remove);
    row.append(keyCell, valueCell, actionCell);
    messagesBody.append(row);
  };

  document.querySelector('.add-message').addEventListener('click', () => {
    addMessage();
    updateMessagesLabel();
  });
  messagesBody.addEventListener('click', event => {
    const button = event.target.closest('.delete-message');
    if (!button) return;
    button.closest('tr').remove();
    reindexMessages();
    updateMessagesLabel();
  });

  const openTrigger = document.getElementById('save-rule-btn');
  const dialog = document.querySelector(openTrigger.dataset.wtDialogTarget);
  openTrigger.addEventListener('click', () => {
    const destination = document.querySelector('.save-messages');
    destination.querySelector('.messages-table')?.remove();
    const originalTable = document.querySelector('.messages-table');
    const clone = originalTable.cloneNode(true);
    const originalInputs = originalTable.querySelectorAll('input');
    clone.querySelectorAll('input').forEach((input, index) => {
      input.value = originalInputs[index].value;
      input.readOnly = true;
      input.setAttribute('form', 'save-rule-form');
    });
    clone.querySelectorAll('tr').forEach(row => row.lastElementChild?.remove());
    destination.append(clone);
    createFunctionReader.setValue(createFunctionEditor.getValue());
    document.getElementById('customSourceCode').value = sourceCodeEditor.getValue();
    dialog.show();
  });
  document.getElementById('cancel-save-rule-dialog')
    .addEventListener('click', () => dialog.close());
  dialog.addEventListener('opened', () => requestAnimationFrame(() => createFunctionReader.refresh()));
  // The create function and messages are folded away; the reader measures itself once shown.
  document.querySelector('[data-save-function]')
    ?.addEventListener('toggle', () => requestAnimationFrame(() => createFunctionReader.refresh()));
})();

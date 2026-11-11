(function() {
  function wireDialog(dialogId, triggerSelector, cancelId, onOpen) {
    var dialog = document.getElementById(dialogId);
    if (!dialog) return;
    var trigger = null;
    document.querySelectorAll(triggerSelector).forEach(function(button) {
      button.addEventListener('click', function() {
        trigger = button;
        if (onOpen) onOpen(button);
        dialog.show();
      });
    });
    var cancel = document.getElementById(cancelId);
    if (cancel) cancel.addEventListener('click', function() { dialog.close(); });
    dialog.addEventListener('closed', function() {
      if (trigger) trigger.focus();
      trigger = null;
    });
  }

  wireDialog('deleteModal', '[data-wt-dialog-target="#deleteModal"]',
      'cancelDeleteModal', function(trigger) {
        document.getElementById('deleteKey').textContent = trigger.dataset.key;
        document.getElementById('deleteLabel').textContent = trigger.dataset.label;
        document.getElementById('deleteFormKey').value = trigger.dataset.key;
      });
  wireDialog('createModal', '[data-wt-dialog-target="#createModal"]', 'cancelCreateModal');

  var secretDialog = document.querySelector('[data-new-api-key-dialog]');
  if (!secretDialog) return;
  var secretField = document.getElementById('newApiKeySecret');
  var copyStatus = secretDialog.querySelector('[data-copy-status]');
  secretDialog.querySelector('[data-copy-api-secret]').addEventListener('click', async function() {
    try {
      await navigator.clipboard.writeText(secretField.value);
      copyStatus.textContent = 'Secret copied.';
    } catch (error) {
      secretField.focus();
      secretField.select();
      copyStatus.textContent = 'Copy was unavailable. The secret is selected for manual copying.';
    }
  });
  secretDialog.querySelector('[data-close-api-secret]').addEventListener('click', function() {
    secretDialog.close();
  });
  secretDialog.addEventListener('opened', function() { secretField.focus(); });
  secretDialog.addEventListener('closed', function() {
    secretField.value = '';
    secretField.removeAttribute('value');
    copyStatus.textContent = '';
    secretDialog.remove();
  });
  customElements.whenDefined('md-dialog').then(function() { secretDialog.show(); });
})();

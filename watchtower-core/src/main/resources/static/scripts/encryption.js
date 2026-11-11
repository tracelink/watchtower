(function() {
  function wire(dialogId, selector, cancelId, onOpen) {
    var dialog = document.getElementById(dialogId);
    if (!dialog) return;
    var activeTrigger = null;
    document.querySelectorAll(selector).forEach(function(trigger) {
      trigger.addEventListener('click', function() {
        activeTrigger = trigger;
        if (onOpen) onOpen(trigger);
        dialog.show();
      });
    });
    var cancel = document.getElementById(cancelId);
    if (cancel) cancel.addEventListener('click', function() { dialog.close(); });
    dialog.addEventListener('closed', function() {
      if (activeTrigger) activeTrigger.focus();
      activeTrigger = null;
    });
  }

  wire('rotateKeyModal', '[data-wt-dialog-target="#rotateKeyModal"]',
      'cancelRotateKeyModal', function(trigger) {
        document.getElementById('rotateModalContent').textContent = trigger.dataset.name;
        document.getElementById('rotateModalInput').value = trigger.dataset.id;
      });
  wire('rotateKeysModal', '[data-wt-dialog-target="#rotateKeysModal"]',
      'cancelRotateKeysModal');
  wire('scheduleModal', '[data-wt-dialog-target="#scheduleModal"]', 'cancelScheduleModal');
})();

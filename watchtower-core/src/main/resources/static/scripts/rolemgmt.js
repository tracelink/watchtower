(function() {
  function wire(dialogId, selector, cancelId, onOpen) {
    var dialog = document.getElementById(dialogId);
    if (!dialog) return;
    var activeTrigger = null;
    document.querySelectorAll(selector).forEach(function(trigger) {
      trigger.addEventListener('click', function() {
        activeTrigger = trigger;
        if (onOpen) onOpen(dialog, trigger);
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
  wire('myModal', '[data-wt-dialog-target="#myModal"]', 'cancelMyModal', function(dialog, trigger) {
    dialog.querySelector('.deleterole').value = trigger.dataset.id;
    dialog.querySelector('.idhere').textContent = trigger.dataset.name;
  });
  wire('createModal', '[data-wt-dialog-target="#createModal"]', 'cancelCreateModal');
})();

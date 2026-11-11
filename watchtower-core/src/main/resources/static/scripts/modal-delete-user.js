(function() {
  var dialog = document.getElementById('myModal');
  if (!dialog) return;
  var activeTrigger = null;
  document.querySelectorAll('[data-wt-dialog-target="#myModal"]').forEach(function(trigger) {
    trigger.addEventListener('click', function() {
      activeTrigger = trigger;
      dialog.querySelector('.deleteuser').value = trigger.dataset.id;
      dialog.querySelector('.idhere').textContent = trigger.dataset.name;
      dialog.show();
    });
  });
  document.getElementById('cancelMyModal').addEventListener('click', function() { dialog.close(); });
  dialog.addEventListener('closed', function() {
    if (activeTrigger) activeTrigger.focus();
    activeTrigger = null;
  });
})();

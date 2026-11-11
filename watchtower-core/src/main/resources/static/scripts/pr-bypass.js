// PR scan report: opens and closes the one bypass dialog from its header button. The dialog holds
// every bypass state (bypass, request, review a request, revoke); the page renders it only while
// the scan blocks, is bypassed, or has a pending request, so a missing dialog means nothing to wire.
(function () {
  "use strict";

  const dialog = document.getElementById("bypassDialog");
  if (!dialog) return;
  let activeTrigger = null;

  document.querySelectorAll('[data-wt-dialog-target="#bypassDialog"]').forEach((trigger) => {
    trigger.addEventListener("click", () => {
      activeTrigger = trigger;
      dialog.show();
    });
  });
  const close = document.getElementById("cancelBypassDialog");
  if (close) close.addEventListener("click", () => dialog.close());
  dialog.addEventListener("closed", () => {
    if (activeTrigger) activeTrigger.focus();
    activeTrigger = null;
  });
})();

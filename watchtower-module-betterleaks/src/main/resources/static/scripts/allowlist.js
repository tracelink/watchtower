// Secrets allowlist page: the add form lives in a dialog opened by "Add entry", and opens by
// itself when the page was reached from a finding ("Allowlist…", data-allowlist-prefill). Scope is
// two buttons (One repository / All repositories); the Repository field is shown only for a
// one-repository entry. An amber chip says what "every rule and no path" will do, only when that
// combination is chosen.
(function () {
  "use strict";

  const dialog = document.getElementById("allowlistDialog");
  if (!dialog) return;
  let activeTrigger = null;

  document.querySelectorAll('[data-wt-dialog-target="#allowlistDialog"]').forEach((trigger) => {
    trigger.addEventListener("click", () => {
      activeTrigger = trigger;
      dialog.show();
    });
  });
  const cancel = document.getElementById("cancelAllowlistDialog");
  if (cancel) cancel.addEventListener("click", () => dialog.close());
  dialog.addEventListener("closed", () => {
    if (activeTrigger) activeTrigger.focus();
    activeTrigger = null;
  });

  const scope = dialog.querySelector("[data-allowlist-scope]");
  const repo = dialog.querySelector("[data-allowlist-repo-field]");
  const path = dialog.querySelector("[data-allowlist-path]");
  const rule = dialog.querySelector("[data-allowlist-rule]");
  const warning = dialog.querySelector("[data-allowlist-warning]");
  const warningText = dialog.querySelector("[data-allowlist-warning-text]");

  function scopeValue() {
    if (!scope) return "REPO";
    // A fieldset of radio buttons, or (older markup) a select
    const checked = scope.querySelector('input[name="scope"]:checked');
    if (checked) return checked.value;
    return scope.value || "REPO";
  }

  function sync() {
    const global = scopeValue() === "GLOBAL";
    if (repo) repo.hidden = global;
    if (!warning) return;
    const everyRule = !rule || !rule.value;
    const noPath = !path || !String(path.value || "").trim();
    warning.hidden = !(everyRule && noPath);
    if (warningText) {
      warningText.textContent = global
        ? "Every rule and no path hides all secrets findings in every repository"
        : "Every rule and no path hides all secrets findings in this repository";
    }
  }
  [scope, path, rule].forEach((field) => {
    if (!field) return;
    field.addEventListener("change", sync);
    field.addEventListener("input", sync);
  });
  sync();

  if (dialog.hasAttribute("data-allowlist-prefill")) {
    dialog.show();
  }
})();

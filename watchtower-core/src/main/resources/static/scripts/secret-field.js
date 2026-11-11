(function () {
  "use strict";

  if (window.wtSecretFieldBound) {
    return;
  }
  window.wtSecretFieldBound = true;

  // A saved secret shows "Saved" and a Replace button (configuration/secretfield.html). Replace
  // reveals the empty field and focuses it; the stored value is never on the page. The listener is
  // on document, so it works however the page arrived: a page opened through a boosted link loads
  // this script after the swap, when DOMContentLoaded and htmx:afterSwap have already fired.
  document.addEventListener("click", (event) => {
    const button = event.target instanceof Element ? event.target.closest("[data-secret-replace]") : null;
    if (!button) {
      return;
    }
    const field = button.closest("[data-secret-field]");
    const input = field && field.querySelector("[data-secret-input]");
    if (!input) {
      return;
    }
    input.hidden = false;
    const saved = field.querySelector("[data-secret-saved]");
    if (saved) {
      saved.hidden = true;
    }
    input.focus();
  });
})();

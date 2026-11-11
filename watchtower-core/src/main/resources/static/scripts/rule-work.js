(function () {
  "use strict";

  // Rule work → Setup gaps (UAT walkthrough, 2026-10-16): tick rules (or the page) and set owner
  // and CWE for all of them from one dialog. The button stays disabled until something is ticked.
  if (window.watchtowerRuleWorkInstalled) {
    return;
  }
  window.watchtowerRuleWorkInstalled = true;

  function boxes() {
    return Array.from(document.querySelectorAll("[data-work-select]"));
  }

  function refresh() {
    const all = boxes();
    const ticked = all.filter((box) => box.checked).length;
    const label = ticked === 1 ? "1 rule" : ticked + " rules";
    const status = document.querySelector("[data-work-selected]");
    if (status) {
      status.textContent = ticked + " selected";
    }
    const count = document.querySelector("[data-work-bulk-count]");
    if (count) {
      count.textContent = label + " selected";
    }
    const open = document.querySelector("[data-work-bulk-open]");
    if (open) {
      open.disabled = ticked === 0;
    }
    const suggest = document.querySelector("[data-work-cwe-open]");
    if (suggest) {
      suggest.disabled = ticked === 0;
    }
    const page = document.querySelector("[data-work-select-all]");
    if (page) {
      page.checked = all.length > 0 && ticked === all.length;
      page.indeterminate = ticked > 0 && ticked < all.length;
    }
  }

  document.addEventListener("change", (event) => {
    const target = event.target;
    if (!(target instanceof window.HTMLInputElement)) {
      return;
    }
    if (target.matches("[data-work-select-all]")) {
      boxes().forEach((box) => {
        box.checked = target.checked;
      });
      refresh();
    } else if (target.matches("[data-work-select]")) {
      refresh();
    }
  });
  document.addEventListener("DOMContentLoaded", refresh);
  document.addEventListener("htmx:afterSwap", refresh);
})();

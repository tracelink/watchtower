// The searchable ruleset picker (fragments/rulesetpicker.html): a button showing the chosen
// ruleset opens a grouped list with a search box. Choosing an option sets the hidden rulesetId,
// which the form posts as before. Code that sets the hidden value directly (the Edit dialog
// filling in a repository's ruleset) dispatches "wt:sync" on it so the label follows; a form
// reset puts the picker back to its starting value. Listeners sit on document, bound once.
(function () {
  "use strict";

  if (window.wtRulesetPickerBound) return;
  window.wtRulesetPickerBound = true;

  const PICKER = "[data-ruleset-picker]";

  const options = (picker) => Array.from(picker.querySelectorAll(".wt-picker-option"));
  const valueInput = (picker) => picker.querySelector("[data-ruleset-value]");
  const panel = (picker) => picker.querySelector("[data-ruleset-panel]");
  const toggle = (picker) => picker.querySelector("[data-ruleset-toggle]");

  // Shows the chosen option's label and icon on the button; an unknown id (a ruleset deleted
  // since) falls back to the first option rather than showing an empty field.
  function sync(picker) {
    const value = valueInput(picker).value;
    const chosen = options(picker).find((option) => option.value === value) || options(picker)[0];
    options(picker).forEach((option) => {
      option.setAttribute("aria-selected", String(option === chosen));
    });
    if (!chosen) return;
    picker.querySelector("[data-ruleset-current]").textContent = chosen.dataset.label || "";
    picker.querySelector("[data-ruleset-icon]").textContent = chosen.dataset.icon || "rule_folder";
  }

  function filter(picker, query) {
    const text = query.trim().toLowerCase();
    let shown = 0;
    options(picker).forEach((option) => {
      const match = !text || (option.dataset.search || option.dataset.label || "").toLowerCase().includes(text);
      option.hidden = !match;
      if (match) shown += 1;
    });
    picker.querySelectorAll("[data-ruleset-group]").forEach((group) => {
      group.hidden = !Array.from(group.querySelectorAll(".wt-picker-option")).some((option) => !option.hidden);
    });
    const empty = picker.querySelector("[data-ruleset-empty]");
    if (empty) empty.hidden = shown > 0;
  }

  function open(picker) {
    document.querySelectorAll(PICKER).forEach((other) => { if (other !== picker) close(other, false); });
    panel(picker).hidden = false;
    toggle(picker).setAttribute("aria-expanded", "true");
    const search = picker.querySelector("[data-ruleset-search]");
    search.value = "";
    filter(picker, "");
    search.focus();
  }

  function close(picker, focusToggle) {
    if (panel(picker).hidden) return;
    panel(picker).hidden = true;
    toggle(picker).setAttribute("aria-expanded", "false");
    if (focusToggle) toggle(picker).focus();
  }

  function choose(picker, option) {
    const input = valueInput(picker);
    input.value = option.value;
    sync(picker);
    close(picker, true);
    input.dispatchEvent(new Event("change", { bubbles: true }));
  }

  document.addEventListener("click", (event) => {
    const picker = event.target.closest(PICKER);
    document.querySelectorAll(PICKER).forEach((other) => { if (other !== picker) close(other, false); });
    if (!picker) return;
    if (event.target.closest("[data-ruleset-toggle]")) {
      if (panel(picker).hidden) open(picker); else close(picker, true);
      return;
    }
    const option = event.target.closest(".wt-picker-option");
    if (option) choose(picker, option);
  });

  document.addEventListener("input", (event) => {
    const search = event.target.closest("[data-ruleset-search]");
    if (search) filter(search.closest(PICKER), search.value);
  });

  document.addEventListener("keydown", (event) => {
    const picker = event.target.closest && event.target.closest(PICKER);
    if (!picker || panel(picker).hidden) return;
    if (event.key === "Escape") {
      // Close only the list, not the dialog around it.
      event.preventDefault();
      event.stopPropagation();
      close(picker, true);
      return;
    }
    if (event.key === "Enter" && event.target.matches("[data-ruleset-search]")) {
      // Enter in the search picks the only match instead of submitting the form.
      event.preventDefault();
      const visible = options(picker).filter((option) => !option.hidden);
      if (visible.length === 1) choose(picker, visible[0]);
      return;
    }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      const visible = options(picker).filter((option) => !option.hidden);
      if (!visible.length) return;
      event.preventDefault();
      const at = visible.indexOf(document.activeElement);
      const next = event.key === "ArrowDown" ? Math.min(at + 1, visible.length - 1) : Math.max(at - 1, 0);
      visible[at < 0 ? 0 : next].focus();
    }
  }, true);

  document.addEventListener("wt:sync", (event) => {
    const picker = event.target.closest && event.target.closest(PICKER);
    if (picker) sync(picker);
  }, true);

  // A form reset (the bulk Edit dialog resets before each use) restores the starting value.
  document.addEventListener("reset", (event) => {
    event.target.querySelectorAll(PICKER).forEach((picker) => {
      valueInput(picker).value = valueInput(picker).dataset.initial || "";
      close(picker, false);
      sync(picker);
    });
  }, true);

  function initialize(scope) {
    scope.querySelectorAll(PICKER).forEach(sync);
  }
  document.addEventListener("htmx:afterSettle", (event) => initialize(event.target));
  initialize(document);
})();

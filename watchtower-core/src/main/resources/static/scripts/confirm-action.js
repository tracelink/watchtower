// Asks before a destructive form is submitted (docs/design-system.md, "Restraint": destructive
// actions confirm). Mark the form, not the button:
//   <form data-confirm="Delete integration X? Scans using it stop connecting."
//         data-confirm-action="Delete integration"> ... </form>
// One shared dialog, built on first use. The listener is on document in the capture phase, so it
// runs before htmx's boosted-form handler, and it survives boosted page swaps. Messages are set
// as text, never markup.
(function () {
  "use strict";

  if (window.wtConfirmActionBound) return;
  window.wtConfirmActionBound = true;

  let dialog = null;
  let pendingForm = null;
  let pendingTrigger = null;

  function element(tag, attributes, text) {
    const el = document.createElement(tag);
    Object.entries(attributes || {}).forEach(([name, value]) => el.setAttribute(name, value));
    if (text) el.textContent = text;
    return el;
  }

  function ensureDialog() {
    if (dialog && dialog.isConnected) return dialog;
    dialog = element("md-dialog", {"data-confirm-dialog": "", type: "alert"});
    dialog.appendChild(element("div", {slot: "headline", "data-confirm-headline": ""}, "Are you sure?"));
    dialog.appendChild(element("p", {slot: "content", "data-confirm-message": ""}));
    const actions = element("div", {slot: "actions"});
    const cancel = element("md-text-button", {type: "button", "data-confirm-cancel": ""}, "Cancel");
    const ok = element("md-filled-button",
      {type: "button", class: "wt-btn-danger", "data-confirm-ok": ""}, "Confirm");
    actions.append(cancel, ok);
    dialog.appendChild(actions);

    cancel.addEventListener("click", () => {
      pendingForm = null;
      dialog.close();
    });
    ok.addEventListener("click", () => {
      const form = pendingForm;
      pendingForm = null;
      dialog.close();
      if (form) {
        form.dataset.confirmed = "true";
        form.requestSubmit();
      }
    });
    dialog.addEventListener("closed", () => {
      if (pendingTrigger && pendingTrigger.isConnected) pendingTrigger.focus();
      pendingTrigger = null;
    });
    document.body.appendChild(dialog);
    return dialog;
  }

  // A delete asks in the same style as every other delete dialog: the delete tile and "Delete X?".
  // Other confirmations keep the plain question. The title is set as text, never markup.
  function showHeadline(headline, form) {
    const action = form.dataset.confirmAction || "Confirm";
    headline.replaceChildren();
    if (!/^Delete/.test(action)) {
      headline.textContent = "Are you sure?";
      return;
    }
    const person = element("span", {class: "wt-person"});
    const tile = element("span", {
      class: "wt-scanner-tile wt-scanner-tile--notrun wt-integration-head__icon",
      "aria-hidden": "true"});
    tile.appendChild(element("span", {class: "material-icons"}, "delete_forever"));
    const text = element("span", {class: "wt-person__text"});
    text.appendChild(element("span", {}, form.dataset.confirmTitle || action + "?"));
    person.append(tile, text);
    headline.appendChild(person);
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.hasAttribute("data-confirm")) return;
    if (form.dataset.confirmed === "true") {
      delete form.dataset.confirmed;
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    const shown = ensureDialog();
    showHeadline(shown.querySelector("[data-confirm-headline]"), form);
    shown.querySelector("[data-confirm-message]").textContent = form.dataset.confirm;
    shown.querySelector("[data-confirm-ok]").textContent =
      form.dataset.confirmAction || "Confirm";
    pendingForm = form;
    pendingTrigger = event.submitter || document.activeElement;
    shown.show();
  }, true);
})();

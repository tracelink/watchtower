// Repository inventory and repository scans: selecting repositories, the selection bar, the
// filter menus, and the dialogs opened from the page bar and rows. A dialog opened for the
// selection (or one row's Scan icon) gets the chosen repository ids copied into its forms.
// Listeners sit on document (bound once), so they keep working after the pager, tabs or a search
// swap #results-region; they only act inside [data-repo-scan], so other pages' dialogs are left
// to their own scripts. Destructive forms confirm through the global data-confirm handler
// (confirm-action.js).
(function () {
  "use strict";

  if (window.wtRepoScanBound) return;
  window.wtRepoScanBound = true;

  const ROOT = "[data-repo-scan]";
  const NOW_TEXT = "Joins the queue now; the run page shows progress";
  const PLAN_TEXT = "Creates a plan on the Plans tab; it first runs at the chosen time";
  let lastTrigger = null;

  const selectedIds = (root) =>
    Array.from(root.querySelectorAll(".wt-repo-select:checked")).map((box) => box.value);

  // "Select all N matching": the change applies to every repository the filter matches,
  // resolved on the server, instead of the ids on this page.
  const isMatching = (root) => root.dataset.matching === "true";

  function hiddenInput(name, value) {
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = value;
    return input;
  }

  function refreshSelection(root) {
    const ids = selectedIds(root);
    const boxes = root.querySelectorAll(".wt-repo-select");
    const bar = root.querySelector("[data-selection-bar]");
    if (ids.length < boxes.length) delete root.dataset.matching;
    const matching = isMatching(root);
    const count = matching && bar ? Number(bar.dataset.matchingTotal) : ids.length;
    root.querySelectorAll("[data-requires-selection]").forEach((button) => {
      button.disabled = count === 0;
    });
    // Actions for the selection appear only once rows are ticked (no disabled grey button).
    root.querySelectorAll("[data-hide-unselected]").forEach((el) => { el.hidden = count === 0; });
    root.querySelectorAll("[data-selection-bar]").forEach((el) => { el.hidden = count === 0; });
    root.querySelectorAll("[data-no-selection]").forEach((el) => { el.hidden = count > 0; });
    // Scan selected carries both attributes: it stays hidden until rows are ticked.
    root.querySelectorAll("[data-no-matching]").forEach((el) => {
      el.hidden = matching || (el.hasAttribute("data-hide-unselected") && count === 0);
    });
    root.querySelectorAll("[data-select-matching]").forEach((el) => {
      el.hidden = matching || boxes.length === 0 || ids.length < boxes.length;
    });
    root.querySelectorAll("[data-selection-count]").forEach((el) => {
      el.textContent = String(count);
    });
    root.querySelectorAll("form[data-bulk-form]").forEach((form) => {
      fillSelectedIds(form, ids, matching);
      if (form.dataset.bulkAction === "delete") {
        form.dataset.confirm = "Delete " + count + (count === 1 ? " repository" : " repositories")
          + " and their repository scan history? Pull request scans stay, and a later pull"
          + " request or sync adds a repository back.";
      }
    });
    const all = root.querySelector("[data-select-all]");
    if (all) {
      all.checked = boxes.length > 0 && ids.length === boxes.length;
      all.indeterminate = ids.length > 0 && ids.length < boxes.length;
    }
  }

  function fillSelectedIds(container, ids, matching) {
    container.querySelectorAll("[data-selected-ids]").forEach((holder) => {
      holder.replaceChildren(...(matching ? [hiddenInput("matching", "true")]
        : ids.map((id) => hiddenInput("repoIds", id))));
    });
  }

  function fillEditDialog(dialog, trigger) {
    const data = trigger.dataset;
    const form = dialog.querySelector("form");
    form.action = form.dataset.actionBase + data.editId;
    dialog.querySelector("[data-edit-title]").textContent = data.editName;
    const project = dialog.querySelector("[data-edit-project]");
    if (project) {
      project.textContent = data.editProject || "";
      project.hidden = !data.editProject;
    }
    // A field is a text field, the ruleset picker's hidden value (told to show the new label),
    // or a row of choice buttons (radios).
    const set = (field, value) => {
      const el = form.querySelector('[data-edit-field="' + field + '"]');
      if (!el) return;
      const text = value == null ? "" : String(value);
      if (el.matches("fieldset")) {
        el.querySelectorAll('input[type="radio"]').forEach((radio) => { radio.checked = radio.value === text; });
        return;
      }
      el.value = text;
      el.dispatchEvent(new Event("wt:sync", { bubbles: true }));
    };
    set("ruleset", data.editRuleset);
    set("team", data.editTeam);
    set("owner", data.editOwner);
    set("labels", data.editLabels);
    set("criticality", data.editCriticality);
    const scanning = form.querySelector('[data-edit-field="scanning"]');
    if (scanning) scanning.checked = data.editPaused !== "true";
  }

  // The selection's one Edit: a single repository opens its own dialog, filled from its row's
  // checkbox; several (or every matching one) open the dialog where blank keeps each value.
  function openEdit(root, button) {
    const ids = selectedIds(root);
    const matching = isMatching(root);
    if (ids.length === 0) return;
    let dialog;
    if (ids.length === 1 && !matching) {
      dialog = root.querySelector("[data-edit-dialog]");
      if (dialog) fillEditDialog(dialog, root.querySelector(".wt-repo-select:checked"));
    } else {
      dialog = root.querySelector("[data-bulk-edit-dialog]");
      if (dialog) {
        const bar = root.querySelector("[data-selection-bar]");
        const count = matching && bar ? Number(bar.dataset.matchingTotal) : ids.length;
        dialog.querySelector("form").reset();
        fillSelectedIds(dialog, ids, matching);
        dialog.querySelector("[data-bulk-edit-title]").textContent =
          "Edit " + count + (count === 1 ? " repository" : " repositories");
        showSelectedNames(dialog, root, matching);
      }
    }
    if (!dialog) return;
    lastTrigger = button;
    dialog.show();
  }

  // The bulk Edit dialog names what it changes: up to five repository chips, then "+ N more".
  function showSelectedNames(dialog, root, matching) {
    const holder = dialog.querySelector("[data-bulk-edit-names]");
    if (!holder) return;
    const names = matching ? [] : Array.from(root.querySelectorAll(".wt-repo-select:checked"))
      .map((box) => box.dataset.editName).filter(Boolean);
    const chips = names.slice(0, 5).map((name) => {
      const chip = document.createElement("span");
      chip.className = "wt-mini-chip wt-meta-chip";
      chip.textContent = name;
      return chip;
    });
    if (names.length > 5) {
      const more = document.createElement("span");
      more.className = "wt-mini-chip";
      more.textContent = "+ " + (names.length - 5) + " more";
      chips.push(more);
    }
    holder.replaceChildren(...chips);
    holder.hidden = chips.length === 0;
  }

  // Titles the dialog and names the plan after what it scans ("payments-api",
  // "3 repositories"), so the Runs list tells one-off scans apart; a typed name wins later.
  function titleScanDialog(dialog, ids, trigger) {
    const title = dialog.querySelector("[data-scan-title]");
    if (!title || dialog.hasAttribute("data-scan-picker")) return;
    const root = trigger.closest(ROOT);
    const checked = ids.length === 1 && root
      ? root.querySelector(".wt-repo-select:checked") : null;
    const repoName = trigger.dataset.repoName || (checked && checked.dataset.editName);
    const label = repoName
      || ids.length + (ids.length === 1 ? " repository" : " repositories");
    title.textContent = "Scan " + label;
    const name = dialog.querySelector('[name="name"]');
    if (name) name.value = label;
  }

  // When is a row of buttons (radios named frequency). A repeating scan shows the time, the
  // day picker that fits it (weekday or day of month: only the shown one is enabled, so only it
  // is posted as "day") and the plan name, and the button becomes "Create plan".
  function showRecurring(dialog) {
    if (!dialog) return;
    const chosen = dialog.querySelector('[data-scan-when] input[name="frequency"]:checked');
    const when = chosen ? chosen.value : "ONCE";
    const recurring = when !== "ONCE";
    dialog.querySelectorAll("[data-scan-recurring]").forEach((el) => { el.hidden = !recurring; });
    dialog.querySelectorAll("[data-scan-day]").forEach((day) => {
      const shown = recurring && day.dataset.scanDay === when;
      day.hidden = !shown;
      day.disabled = !shown;
    });
    dialog.querySelectorAll("[data-scan-next]").forEach((el) => {
      el.textContent = recurring ? PLAN_TEXT : NOW_TEXT;
    });
    dialog.querySelectorAll("[data-scan-next-icon]").forEach((el) => {
      el.textContent = recurring ? "event_repeat" : "schedule_send";
    });
    dialog.querySelectorAll("[data-scan-submit]").forEach((el) => {
      el.textContent = recurring ? "Create plan" : "Scan";
    });
    dialog.querySelectorAll("[data-scan-submit-icon]").forEach((el) => {
      el.textContent = recurring ? "event_repeat" : "play_arrow";
    });
  }

  // New scan's Repositories: each name or pattern becomes a chip; the chips are posted as the
  // selector, one per line, as the text area posted them.
  function targetsOf(dialog) {
    return Array.from(dialog.querySelectorAll("[data-scan-target-chips] [data-target]"))
      .map((chip) => chip.dataset.target);
  }

  function syncTargets(dialog) {
    const selector = dialog.querySelector("[data-scan-selector]");
    if (selector) selector.value = targetsOf(dialog).join("\n");
  }

  function addTarget(dialog, text) {
    const value = text.trim();
    if (!value || targetsOf(dialog).includes(value)) return;
    const chip = document.createElement("span");
    chip.className = "wt-mini-chip wt-meta-chip wt-chip-input__chip";
    chip.dataset.target = value;
    const label = document.createElement("span");
    label.textContent = value;
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "wt-chip-input__remove";
    remove.setAttribute("aria-label", "Remove " + value);
    remove.dataset.scanTargetRemove = "";
    const icon = document.createElement("span");
    icon.className = "material-icons";
    icon.setAttribute("aria-hidden", "true");
    icon.textContent = "close";
    remove.appendChild(icon);
    chip.append(label, remove);
    dialog.querySelector("[data-scan-target-chips]").appendChild(chip);
    syncTargets(dialog);
    const error = dialog.querySelector("[data-scan-target-error]");
    if (error) error.hidden = true;
  }

  // Pending text counts as a chip; an empty target list stops the submit with a message.
  function checkTargets(form, event) {
    const dialog = form.closest("md-dialog");
    const input = dialog && dialog.querySelector("[data-scan-target-input]");
    if (!input) return;
    if (input.value.trim()) {
      addTarget(dialog, input.value);
      input.value = "";
    }
    if (targetsOf(dialog).length === 0) {
      event.preventDefault();
      const error = dialog.querySelector("[data-scan-target-error]");
      if (error) error.hidden = false;
      input.focus();
    }
  }

  document.addEventListener("keydown", (event) => {
    const input = event.target.closest && event.target.closest("[data-scan-target-input]");
    if (!input || !input.closest(ROOT)) return;
    if (event.key === "Enter" || event.key === ",") {
      event.preventDefault();
      addTarget(input.closest("md-dialog"), input.value);
      input.value = "";
    } else if (event.key === "Backspace" && !input.value) {
      const chips = input.closest("md-dialog").querySelectorAll("[data-scan-target-chips] [data-target]");
      if (chips.length) {
        chips[chips.length - 1].remove();
        syncTargets(input.closest("md-dialog"));
      }
    }
  });

  document.addEventListener("submit", (event) => {
    if (event.target.matches("[data-scan-form]") && event.target.closest(ROOT)) {
      checkTargets(event.target, event);
    }
  }, true);

  // The repository search pill filters as you type. The swap replaces the field, so the new one
  // gets the focus and caret back (Fixes board 2026-10-22).
  const SEARCH_DELAY_MS = 350;
  let searchTimer = null;
  let refocusSearch = false;
  document.addEventListener("input", (event) => {
    const search = event.target.closest("[data-repository-search]");
    if (!search || !search.closest(ROOT)) return;
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(() => {
      const form = search.closest("form");
      if (!form) return;
      refocusSearch = true;
      form.requestSubmit();
    }, SEARCH_DELAY_MS);
  });
  document.addEventListener("htmx:afterSettle", () => {
    if (!refocusSearch) return;
    refocusSearch = false;
    const search = document.querySelector(ROOT + " [data-repository-search]");
    if (!search) return;
    search.focus();
    const end = String(search.value || "").length;
    if (typeof search.setSelectionRange === "function") search.setSelectionRange(end, end);
  });

  document.addEventListener("change", (event) => {
    const root = event.target.closest(ROOT);
    if (!root) return;
    if (event.target.matches("[data-select-all]")) {
      root.querySelectorAll(".wt-repo-select").forEach((box) => {
        box.checked = event.target.checked;
      });
    }
    if (event.target.matches("[data-select-all], .wt-repo-select")) refreshSelection(root);
    if (event.target.closest("[data-auto-submit]")) {
      const form = event.target.closest("form");
      if (form) form.requestSubmit();
    }
    if (event.target.closest("[data-scan-when]")) {
      showRecurring(event.target.closest("md-dialog"));
    }
    const fileInput = event.target.closest("[data-import-file]");
    if (fileInput) {
      const name = fileInput.closest("md-dialog").querySelector("[data-import-file-name]");
      if (name) name.textContent = fileInput.files && fileInput.files.length ? fileInput.files[0].name : "Drop a CSV file or browse";
    }
  });

  document.addEventListener("click", (event) => {
    const close = event.target.closest("md-dialog [data-dialog-close]");
    if (close && close.closest(ROOT)) {
      close.closest("md-dialog").close();
      return;
    }
    const removeTarget = event.target.closest("[data-scan-target-remove]");
    if (removeTarget && removeTarget.closest(ROOT)) {
      const dialog = removeTarget.closest("md-dialog");
      removeTarget.closest("[data-target]").remove();
      syncTargets(dialog);
      dialog.querySelector("[data-scan-target-input]").focus();
      return;
    }
    const clear = event.target.closest("[data-selection-clear]");
    if (clear && clear.closest(ROOT)) {
      const root = clear.closest(ROOT);
      delete root.dataset.matching;
      root.querySelectorAll(".wt-repo-select").forEach((box) => { box.checked = false; });
      refreshSelection(root);
      return;
    }
    const selectMatching = event.target.closest("[data-select-matching]");
    if (selectMatching && selectMatching.closest(ROOT)) {
      const root = selectMatching.closest(ROOT);
      root.dataset.matching = "true";
      refreshSelection(root);
      return;
    }
    // A finding's location opens its file in the report's Code section (which loads its code)
    const codeLink = event.target.closest("a[data-code-file], a[data-detail-source]");
    if (codeLink && codeLink.closest(ROOT)) {
      const file = Array.from(codeLink.closest(ROOT).querySelectorAll("details[data-file]"))
        .find((details) => details.dataset.file === (codeLink.dataset.codeFile || codeLink.dataset.file));
      if (file) {
        event.preventDefault();
        file.open = true;
        file.scrollIntoView({block: "start"});
      }
      return;
    }
    const edit = event.target.closest("[data-edit-selection]");
    if (edit && edit.closest(ROOT)) {
      openEdit(edit.closest(ROOT), edit);
      return;
    }
    const trigger = event.target.closest("[data-wt-dialog-target]");
    const root = trigger && trigger.closest(ROOT);
    if (!root) return;
    const dialog = root.querySelector(trigger.getAttribute("data-wt-dialog-target"));
    if (!dialog) return;
    const ids = trigger.dataset.repoId ? [trigger.dataset.repoId]
      : trigger.hasAttribute("data-requires-selection") ? selectedIds(root) : null;
    const matching = !trigger.dataset.repoId && isMatching(root);
    if (ids) {
      if (ids.length === 0) return;
      fillSelectedIds(dialog, ids, matching);
      if (dialog.hasAttribute("data-scan-dialog")) titleScanDialog(dialog, ids, trigger);
    }
    if (dialog.hasAttribute("data-edit-dialog")) fillEditDialog(dialog, trigger);
    if (dialog.hasAttribute("data-scan-dialog")) showRecurring(dialog);
    lastTrigger = trigger;
    dialog.show();
  });

  // md-dialog's "closed" does not bubble, so listen in the capture phase. Focus goes back to
  // the button that opened the dialog (docs/design-system.md, "Focus and feedback").
  document.addEventListener("closed", (event) => {
    if (!(event.target instanceof Element) || !event.target.closest(ROOT)) return;
    if (lastTrigger && lastTrigger.isConnected) lastTrigger.focus();
    lastTrigger = null;
  }, true);

  // A swap (pager, tab, search) brings new rows with nothing selected.
  document.addEventListener("htmx:afterSettle", () => {
    document.querySelectorAll(ROOT).forEach(refreshSelection);
  });
  document.querySelectorAll(ROOT).forEach(refreshSelection);

  // A repository sync runs in the background. While one does, the sync button is off and spinning; the page
  // checks back and reloads once, when the button is no longer marked, so a selection is not lost meanwhile.
  var SYNC_POLL_MS = 5000;
  if (document.querySelector('[data-sync-running]')) {
    var syncPoll = setInterval(function () {
      fetch(window.location.href, {credentials: 'same-origin'})
        .then(function (response) { return response.ok ? response.text() : null; })
        .then(function (html) {
          if (html !== null && html.indexOf('data-sync-running') === -1) {
            clearInterval(syncPoll);
            window.location.reload();
          }
        })
        .catch(function () { /* try again at the next tick */ });
    }, SYNC_POLL_MS);
  }
})();

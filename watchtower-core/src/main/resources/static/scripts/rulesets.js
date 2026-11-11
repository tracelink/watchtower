(function () {
  "use strict";

  // The ruleset picker is a menu of links; show the loading line while the next ruleset opens.
  document.querySelectorAll("[data-ruleset-link]").forEach((link) => {
    if (link.dataset.initialized) {
      return;
    }
    link.dataset.initialized = "true";
    link.addEventListener("click", () => {
      const region = document.querySelector("[data-ruleset-region]");
      const loading = document.querySelector("[data-ruleset-loading]");
      if (region) region.setAttribute("aria-busy", "true");
      if (loading) loading.hidden = false;
    });
  });

  // Dialogs open from the More menu (closing the menu) and from inside another dialog (Delete
  // in Ruleset settings closes settings first). Cancel and × use data-wt-dialog-close (wt-dialog.js).
  const opened = {};
  const returnFocus = new WeakMap();
  const replacedDialogs = new WeakSet();
  [
    "createRulesetModal",
    "defaultRulesetModal",
    "importModal",
    "editRulesModal",
    "editRulesetModal",
    "deleteRulesetModal",
    "rulesetInheritanceModal"
  ].forEach((dialogId) => {
    const dialog = document.getElementById(dialogId);
    if (!dialog || dialog.dataset.initialized) {
      return;
    }
    dialog.dataset.initialized = "true";
    dialog.addEventListener("closed", () => {
      if (replacedDialogs.delete(dialog)) return;
      const trigger = returnFocus.get(dialog);
      if (trigger?.isConnected && ![...document.querySelectorAll("md-dialog")].some(other => other.open)) {
        trigger.focus();
      }
    });
    document.querySelectorAll(`[data-wt-dialog-target="#${dialogId}"]`).forEach((trigger) => {
      trigger.addEventListener("click", () => {
        const menu = trigger.closest("details[open]");
        const parent = trigger.closest("md-dialog");
        // A menu item becomes hidden when More closes; return to its visible summary instead.
        returnFocus.set(dialog, menu?.querySelector("summary") || returnFocus.get(parent) || trigger);
        menu?.removeAttribute("open");
        if (parent && parent !== dialog && typeof parent.close === "function") {
          replacedDialogs.add(parent);
          parent.close();
        }
        dialog.show();
        opened[dialogId]?.(dialog);
      });
    });
  });

  // "Blocks a pull request at": say what the chosen level means as it changes.
  const blocking = document.querySelector("[data-blocking-level]");
  const blockingHelp = blocking?.querySelector("[data-blocking-help]");
  if (blocking && blockingHelp) {
    blocking.addEventListener("change", (event) => {
      const name = event.target?.dataset?.levelName;
      if (name) blockingHelp.textContent = `Findings at ${name} or above block; lower ones only comment.`;
    });
  }

  // Include other rulesets: search filters the grouped list; groups with no match hide.
  const includeSearch = document.querySelector("[data-ruleset-include-search]");
  if (includeSearch) {
    includeSearch.addEventListener("input", () => {
      const query = includeSearch.value.trim().toLowerCase();
      let any = false;
      document.querySelectorAll("[data-include-group]").forEach((group) => {
        let groupHasMatch = false;
        group.querySelectorAll("[data-include-option]").forEach((option) => {
          const match = query === "" || (option.dataset.search || "").includes(query);
          option.hidden = !match;
          groupHasMatch = groupHasMatch || match;
        });
        group.hidden = !groupHasMatch;
        any = any || groupHasMatch;
      });
      const empty = document.querySelector("[data-include-empty]");
      if (empty) empty.hidden = any;
    });
  }

  // Rules in this ruleset: the list loads when the dialog first opens (scalars from
  // /rulesets/{id}/rules/choices), so the page itself never renders every rule. The form posts
  // the complete set of ticked rule ids, as before.
  const rulesDialog = document.getElementById("editRulesModal");
  if (rulesDialog && !rulesDialog.dataset.choicesReady) {
    rulesDialog.dataset.choicesReady = "true";
    const list = rulesDialog.querySelector("[data-rule-choices-list]");
    const status = rulesDialog.querySelector("[data-rule-choices-status]");
    const search = rulesDialog.querySelector("[data-rule-choices-search]");
    const scannerSelect = rulesDialog.querySelector("[data-rule-choices-scanner]");
    const count = rulesDialog.querySelector("[data-rule-choices-count]");
    const save = rulesDialog.querySelector("[data-rule-choices-save]");
    const selectedInputs = rulesDialog.querySelector("[data-rule-choices-selected]");
    const form = rulesDialog.querySelector("#editRulesModalForm");
    const selected = new Set();
    let rules = null;
    let loading = false;
    let kind = "custom";

    const element = (tag, className, text) => {
      const el = document.createElement(tag);
      if (className) el.className = className;
      if (text != null) el.textContent = text;
      return el;
    };
    const updateCount = () => {
      if (count) count.textContent = selected.size.toLocaleString("en-US");
    };
    // Zero-width characters in a stored rule name must not hide it from a typed search.
    const searchable = (text) => (text || "").replace(/[\u200b-\u200d\u2060\ufeff]/g, "").toLowerCase();
    const shown = () => {
      const query = searchable((search?.value || "").trim());
      const scanner = scannerSelect?.value || "";
      return (rules || []).filter((rule) => (kind === "custom") === rule.custom
        && (scanner === "" || rule.scanner === scanner)
        && (query === "" || searchable(rule.name).includes(query)));
    };
    const render = () => {
      if (!list || !rules) return;
      const visible = shown();
      list.replaceChildren(...visible.map((rule) => {
        const option = element("label", "wt-picker-option wt-check-option");
        const box = element("input");
        box.type = "checkbox";
        box.value = String(rule.id);
        box.checked = selected.has(rule.id);
        box.addEventListener("change", () => {
          if (box.checked) selected.add(rule.id); else selected.delete(rule.id);
          updateCount();
        });
        const tile = element("span", "wt-scanner-tile wt-scanner-tile--ran wt-picker-tile");
        tile.setAttribute("aria-hidden", "true");
        tile.appendChild(element("span", "material-icons", rule.icon));
        option.append(box, tile, element("span", null, rule.name));
        if (rule.retired) {
          option.appendChild(element("span", "wt-mini-chip", "Retired"));
        }
        return option;
      }));
      if (status) {
        status.textContent = visible.length === 0 ? "No rule matches."
          : `${visible.length.toLocaleString("en-US")} shown`;
      }
    };
    const load = async () => {
      if (rules || loading) return;
      loading = true;
      if (status) status.textContent = 'Loading rules…';
      try {
        const response = await fetch(rulesDialog.dataset.choicesUrl, {headers: {Accept: "application/json"}});
        if (!response.ok) throw new Error("The rule list could not be loaded. Close and open the dialog again.");
        const body = await response.json();
        rules = Array.isArray(body.rules) ? body.rules : [];
        rules.filter((rule) => rule.selected).forEach((rule) => selected.add(rule.id));
        (body.scanners || []).forEach((scanner) => {
          const option = element("option", null, scanner.name);
          option.value = scanner.key;
          scannerSelect?.appendChild(option);
        });
        if (!rules.some((rule) => rule.custom)) setKind("provided");
        updateCount();
        render();
        if (save) save.disabled = false;
      } catch (error) {
        if (status) status.textContent = error.message;
      } finally {
        loading = false;
      }
    };
    const setKind = (value) => {
      kind = value;
      rulesDialog.querySelectorAll("[data-rule-choices-kind]").forEach((button) => {
        const active = button.dataset.ruleChoicesKind === value;
        button.classList.toggle("is-active", active);
        button.setAttribute("aria-pressed", String(active));
      });
    };
    rulesDialog.querySelectorAll("[data-rule-choices-kind]").forEach((button) => {
      button.addEventListener("click", () => { setKind(button.dataset.ruleChoicesKind); render(); });
    });
    search?.addEventListener("input", render);
    scannerSelect?.addEventListener("change", render);
    const tickShown = (value) => {
      shown().forEach((rule) => { if (value) selected.add(rule.id); else selected.delete(rule.id); });
      updateCount();
      render();
    };
    rulesDialog.querySelector("[data-rule-choices-all]")?.addEventListener("click", () => tickShown(true));
    rulesDialog.querySelector("[data-rule-choices-none]")?.addEventListener("click", () => tickShown(false));
    form?.addEventListener("submit", (event) => {
      if (!rules) {
        event.preventDefault();
        return;
      }
      selectedInputs.replaceChildren(...Array.from(selected).map((id) => {
        const input = element("input");
        input.type = "hidden";
        input.name = "ruleIds";
        input.value = String(id);
        return input;
      }));
    });
    opened.editRulesModal = load;
  }

  // Ruleset import (UAT #26): show what the chosen file would change before Import is enabled.
  const importForm = document.getElementById("importModalForm");
  const importFile = importForm?.querySelector("[data-import-file]");
  const importPreview = importForm?.querySelector("[data-import-preview]");
  const importSubmit = document.querySelector("[data-import-submit]");
  if (importForm && importFile && importPreview && importSubmit && !importForm.dataset.previewReady) {
    importForm.dataset.previewReady = "true";
    let previewVersion = 0;
    const line = (parent, text, tag = "p") => {
      const element = document.createElement(tag);
      element.textContent = text;
      parent.appendChild(element);
      return element;
    };
    const renderPreview = (preview) => {
      importPreview.replaceChildren();
      line(importPreview, preview.existingRuleset
        ? `Updates the existing ruleset "${preview.rulesetName}".`
        : `Creates a new ruleset "${preview.rulesetName}".`);
      const counts = line(importPreview, "", "ul");
      line(counts, `${preview.newRules} new rules`, "li");
      line(counts, `${preview.updatedRules} existing custom rules updated`, "li");
      line(counts, `${preview.priorityOnlyRules} provided rules: priority only`, "li");
      if (preview.removedCount > 0) {
        line(counts, `${preview.removedCount} rules removed from this ruleset (not deleted): `
          + preview.removedFromRuleset.join(", ") + (preview.removedCount > preview.removedFromRuleset.length ? ", …" : ""), "li");
      }
      if (preview.problems.length > 0) {
        line(importPreview, "Import is blocked until these are fixed:");
        const problems = line(importPreview, "", "ul");
        preview.problems.forEach((problem) => line(problems, problem, "li"));
      }
      importSubmit.disabled = preview.problems.length > 0;
    };
    importFile.addEventListener("change", async () => {
      const version = ++previewVersion;
      importSubmit.disabled = true;
      importPreview.replaceChildren();
      const fileName = importForm.querySelector("[data-import-file-name]");
      if (!importFile.files || importFile.files.length === 0) {
        if (fileName) fileName.textContent = "Drop a ruleset JSON file or browse";
        return;
      }
      if (fileName) fileName.textContent = importFile.files[0].name;
      line(importPreview, "Checking the file…");
      try {
        const response = await fetch(`${importForm.action}/preview`, {method: "POST", body: new FormData(importForm)});
        const body = await response.json().catch(() => ({}));
        if (version !== previewVersion) return;
        if (!response.ok) {
          throw new Error(body.error || "The file could not be checked.");
        }
        renderPreview(body);
      } catch (error) {
        if (version !== previewVersion) return;
        importPreview.replaceChildren();
        line(importPreview, error.message);
      }
    });
    importForm.addEventListener('submit', (event) => {
      if (importSubmit.disabled) event.preventDefault();
    });
  }
})();

// Alert Settings dialogs: one add/edit dialog each for routes and channels, plus a shared
// delete confirmation. Triggers carry their values in data-* attributes; webhook URLs are never
// rendered, so editing a channel leaves the URL blank (blank keeps the stored one).
(function () {
  "use strict";

  const ROUTE_ADD_ACTION = "/alertsettings/routes/add";
  const ROUTE_UPDATE_ACTION = "/alertsettings/routes/update";
  const CHANNEL_ADD_ACTION = "/alertsettings/channels/add";
  const CHANNEL_UPDATE_ACTION = "/alertsettings/channels/update";
  const ROUTE_DEFAULTS = {
    alertType: "", channelId: "", aggregation: "PER_SCAN", dedupeWindowHours: "720",
    minPriority: "", apiLabelFilter: "", repoInclude: "", repoExclude: ""
  };

  function wire(dialogId, cancelId, onOpen) {
    const dialog = document.getElementById(dialogId);
    if (!dialog) return;
    let activeTrigger = null;
    document.querySelectorAll('[data-wt-dialog-target="#' + dialogId + '"]').forEach((trigger) => {
      trigger.addEventListener("click", () => {
        activeTrigger = trigger;
        onOpen(dialog, trigger);
        dialog.show();
      });
    });
    const cancel = document.getElementById(cancelId);
    if (cancel) cancel.addEventListener("click", () => dialog.close());
    dialog.addEventListener("closed", () => {
      if (activeTrigger) activeTrigger.focus();
      activeTrigger = null;
    });
  }

  function setText(root, selector, text) {
    const element = root.querySelector(selector);
    if (element) element.textContent = text;
  }

  function setHidden(input, value) {
    if (!input) return;
    input.value = value == null ? "" : value;
    input.disabled = value == null;
  }

  // Choices drawn as buttons (radio inputs): tick the one with this value. An integration filter
  // naming an integration that no longer exists gets its own button, so editing keeps it.
  function chooseRadio(form, name, value) {
    const wanted = value == null ? "" : String(value);
    const radios = Array.from(form.querySelectorAll(`input[type="radio"][name="${name}"]`));
    let match = radios.find((radio) => radio.value === wanted);
    if (!match && name === "apiLabelFilter" && wanted !== "") {
      const label = document.createElement("label");
      label.className = "wt-choice-chip";
      label.dataset.routeExtra = "";
      match = document.createElement("input");
      match.type = "radio";
      match.name = name;
      match.value = wanted;
      match.setAttribute("aria-label", "Only " + wanted);
      const text = document.createElement("span");
      text.textContent = wanted;
      label.append(match, text);
      form.querySelector("[data-route-integrations]")?.appendChild(label);
    }
    const chosen = match || radios[0];
    if (chosen) chosen.checked = true;
  }

  // "Don't repeat for": 1 / 7 / 30 days, or Custom hours. The form still posts dedupeWindowHours.
  const REPEAT_PRESETS = ["24", "168", "720"];
  function syncRepeat(form) {
    const hidden = form.querySelector('[data-route-field="dedupeWindowHours"]');
    const custom = form.querySelector("[data-route-repeat-custom]");
    const hours = form.querySelector("[data-route-repeat-hours]");
    const choice = form.querySelector('input[name="repeatChoice"]:checked');
    const isCustom = !choice || choice.value === "custom";
    if (custom) custom.hidden = !isCustom;
    if (hours) hours.required = isCustom;
    if (hidden) hidden.value = isCustom ? (hours ? hours.value : hidden.value) : choice.value;
  }
  function setRepeat(form, value) {
    const hours = String(value || "720");
    const preset = REPEAT_PRESETS.includes(hours) ? hours : "custom";
    form.querySelectorAll('input[name="repeatChoice"]').forEach((radio) => {
      radio.checked = radio.value === preset;
    });
    const field = form.querySelector("[data-route-repeat-hours]");
    if (field) field.value = hours;
    syncRepeat(form);
  }

  function openRouteDialog(dialog, trigger) {
    const editing = trigger.hasAttribute("data-route-edit");
    const data = trigger.dataset;
    const values = editing ? {
      alertType: data.alertType, channelId: data.channelId, aggregation: data.aggregation,
      dedupeWindowHours: data.dedupe, minPriority: data.minPriority,
      apiLabelFilter: data.apiLabel, repoInclude: data.repoInclude, repoExclude: data.repoExclude
    } : ROUTE_DEFAULTS;
    const form = dialog.querySelector("#routeForm");
    form.setAttribute("action", editing ? ROUTE_UPDATE_ACTION : ROUTE_ADD_ACTION);
    setHidden(form.querySelector("[data-route-id]"), editing ? data.id : null);
    form.querySelectorAll("[data-route-extra]").forEach((extra) => extra.remove());
    form.querySelectorAll("[data-route-field]").forEach((field) => {
      const value = values[field.dataset.routeField];
      field.value = value == null ? "" : value;
    });
    ["aggregation", "minPriority", "apiLabelFilter"].forEach((name) => chooseRadio(form, name, values[name]));
    setRepeat(form, values.dedupeWindowHours);
    setText(dialog, "[data-route-dialog-title]", editing ? "Edit route" : "Add route");
    setText(dialog, "[data-route-submit]", editing ? "Save route" : "Add route");
    setText(dialog, "[data-route-submit-icon]", editing ? "save" : "add");
  }

  const routeForm = document.getElementById("routeForm");
  if (routeForm && !routeForm.dataset.repeatReady) {
    routeForm.dataset.repeatReady = "true";
    routeForm.addEventListener("change", (event) => {
      if (event.target?.name === "repeatChoice") syncRepeat(routeForm);
    });
    routeForm.addEventListener("input", (event) => {
      if (event.target?.hasAttribute?.("data-route-repeat-hours")) syncRepeat(routeForm);
    });
    routeForm.addEventListener("submit", () => syncRepeat(routeForm));
  }

  function openChannelDialog(dialog, trigger) {
    const editing = trigger.hasAttribute("data-channel-edit");
    const data = trigger.dataset;
    const form = dialog.querySelector("#channelForm");
    form.setAttribute("action", editing ? CHANNEL_UPDATE_ACTION : CHANNEL_ADD_ACTION);
    setHidden(form.querySelector("[data-channel-id]"), editing ? data.id : null);
    // Enable/Disable is part of editing; a new channel is always enabled.
    const enabled = form.querySelector("[data-channel-enabled]");
    if (enabled) {
      enabled.disabled = !editing;
      enabled.checked = editing && data.enabled === "true";
    }
    const enabledRow = form.querySelector("[data-channel-enabled-row]");
    if (enabledRow) enabledRow.hidden = !editing;
    const name = form.querySelector("[data-channel-name]");
    if (name) name.value = editing ? data.name : "";
    const url = form.querySelector("[data-channel-url]");
    if (url) {
      url.value = "";
      url.required = !editing;
      url.setAttribute("supporting-text", editing
          ? "Leave blank to keep the current URL"
          : "https://chat.googleapis.com/v1/spaces/.../messages?key=...&token=...");
    }
    setText(dialog, "[data-channel-dialog-title]", editing ? "Edit channel" : "Add channel");
    setText(dialog, "[data-channel-submit]", editing ? "Save channel" : "Add channel");
  }

  function openDeleteDialog(dialog, trigger) {
    const form = dialog.querySelector("#confirmDeleteForm");
    form.setAttribute("action", trigger.dataset.deleteAction);
    form.querySelector("[data-delete-id-field]").value = trigger.dataset.deleteId;
    setText(dialog, "[data-delete-name]", trigger.dataset.deleteLabel);
    const title = trigger.dataset.deleteTitle || "Delete";
    dialog.querySelectorAll("[data-delete-title]").forEach((element) => { element.textContent = title; });
  }

  wire("routeDialog", "cancelRouteDialog", openRouteDialog);
  wire("channelDialog", "cancelChannelDialog", openChannelDialog);
  wire("confirmDeleteDialog", "cancelConfirmDeleteDialog", openDeleteDialog);
})();

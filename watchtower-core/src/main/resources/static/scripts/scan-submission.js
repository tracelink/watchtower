(function () {
  "use strict";

  if (window.wtScanSubmissionBound) {
    return;
  }
  window.wtScanSubmissionBound = true;
  // Recent scans are the five newest, with "View all results" for more, so they need no paging.
  // Admin forms marked data-confirm are confirmed by confirm-action.js (loaded on every page).

  function resetForm(form) {
    delete form.dataset.submitting;
    const button = form.querySelector("[data-submit-button]");
    if (button) {
      button.disabled = false;
    }
    const status = form.querySelector(".wt-submit-status");
    if (status) {
      status.textContent = "";
    }
  }

  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) {
      return;
    }

    if (!form.matches("[data-scan-submission]")) {
      return;
    }
    if (form.dataset.submitting === "true") {
      event.preventDefault();
      return;
    }

    form.dataset.submitting = "true";
    const button = form.querySelector("[data-submit-button]");
    if (button) {
      button.disabled = true;
    }
    const status = form.querySelector(".wt-submit-status");
    if (status) {
      status.textContent = "Submitting scan…";
    }
  });

  document.addEventListener("dragenter", (event) => {
    const zone = event.target.closest?.(".wt-drop-zone");
    if (zone) {
      zone.classList.add("is-dragging");
    }
  });
  document.addEventListener("dragleave", (event) => {
    const zone = event.target.closest?.(".wt-drop-zone");
    if (zone && !zone.contains(event.relatedTarget)) {
      zone.classList.remove("is-dragging");
    }
  });
  document.addEventListener("drop", (event) => {
    event.target.closest?.(".wt-drop-zone")?.classList.remove("is-dragging");
  });
  // The chosen upload shows as a chip in the drop zone; its x clears the file again.
  function formatSize(bytes) {
    return bytes >= 1048576 ? (bytes / 1048576).toFixed(1) + " MB" : Math.max(1, Math.round(bytes / 1024)) + " KB";
  }
  function showChosenFile(input) {
    const zone = input.closest(".wt-drop-zone");
    const chip = zone?.querySelector("[data-upload-file-chip]");
    if (!chip) {
      return;
    }
    const file = input.files && input.files[0];
    chip.hidden = !file;
    zone.querySelector(".wt-drop-zone__title")?.toggleAttribute("hidden", Boolean(file));
    if (file) {
      chip.querySelector("[data-upload-file-name]").textContent = file.name + " · " + formatSize(file.size);
    }
  }
  document.addEventListener("change", (event) => {
    if (event.target.matches?.("input[data-upload-file]")) {
      showChosenFile(event.target);
    }
  });
  document.addEventListener("click", (event) => {
    const clear = event.target.closest?.("[data-upload-file-clear]");
    if (!clear) {
      return;
    }
    event.preventDefault();
    const input = clear.closest(".wt-drop-zone").querySelector("input[data-upload-file]");
    input.value = "";
    showChosenFile(input);
  });
  window.addEventListener("pageshow", () => {
    document.querySelectorAll("form[data-scan-submission]").forEach(resetForm);
  });
})();

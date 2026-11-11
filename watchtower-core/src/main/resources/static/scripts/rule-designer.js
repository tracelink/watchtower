(function () {
  'use strict';

  const workspaces = document.querySelectorAll('[data-rule-designer]');

  workspaces.forEach(function (workspace) {
    const status = workspace.querySelector('[data-designer-status]');
    const runForms = workspace.querySelectorAll('[data-designer-run-form]');
    const inputs = workspace.querySelectorAll('[data-designer-input]');

    workspace.dataset.dirty = 'false';

    inputs.forEach(function (input) {
      input.addEventListener('input', function () {
        workspace.dataset.dirty = 'true';
      });
      input.addEventListener('change', function () {
        workspace.dataset.dirty = 'true';
      });
    });

    runForms.forEach(function (form) {
      form.addEventListener('submit', function () {
        workspace.dataset.dirty = 'false';
        workspace.setAttribute('aria-busy', 'true');
        const runButton = form.querySelector('[data-run-rule]');
        if (runButton) {
          runButton.disabled = true;
        }
        if (status) {
          status.textContent = 'Running rule…';
        }
      });
    });
  });

  // Match chips (UAT walkthrough, 2026-10-16): each designer script hands over its sample editor
  // once it exists; the matched lines are highlighted and "Line N" jumps to that line.
  window.wtDesignerMatches = function (editor) {
    const chips = Array.from(document.querySelectorAll('[data-designer-match-line]'));
    if (!editor || chips.length === 0) {
      return;
    }
    const lines = chips.map(function (chip) { return Number(chip.dataset.designerMatchLine); });
    if (typeof editor.highlightLines === 'function') {
      editor.highlightLines(lines);
    }
    chips.forEach(function (chip) {
      chip.addEventListener('click', function () {
        if (typeof editor.jumpToLine === 'function') {
          editor.jumpToLine(Number(chip.dataset.designerMatchLine));
        }
      });
    });
  };

  if (!window.wtRuleDesignerNavigationGuard) {
    window.wtRuleDesignerNavigationGuard = true;
    window.addEventListener('beforeunload', function (event) {
      const dirtyWorkspace = document.querySelector('[data-rule-designer][data-dirty="true"]');
      if (!dirtyWorkspace) {
        return;
      }
      event.preventDefault();
      event.returnValue = '';
    });
    document.addEventListener('htmx:beforeRequest', function (event) {
      const dirtyWorkspace = document.querySelector('[data-rule-designer][data-dirty="true"]');
      const requestElement = event.detail && event.detail.elt;
      if (!dirtyWorkspace || (requestElement && dirtyWorkspace.contains(requestElement))) {
        return;
      }
      if (!window.confirm('Discard your unsaved rule designer changes?')) {
        event.preventDefault();
      }
    });
  }

  // A rule opened from an assistant draft: its save form carries the draft's id, so the server can give the
  // new rule the draft's CWE and close the draft. Every designer's save form posts to /designer/<scanner>/save.
  if (!window.wtDraftSaveInstalled) {
    window.wtDraftSaveInstalled = true;
    document.addEventListener('submit', function (event) {
      const form = event.target;
      const banner = document.querySelector('[data-draft-banner]');
      if (!banner || !banner.dataset.draftId || !(form instanceof HTMLFormElement)) {
        return;
      }
      if (!/^\/designer\/[a-z]+\/save$/.test(form.getAttribute('action') || '') || form.querySelector('input[name="draft"]')) {
        return;
      }
      const field = document.createElement('input');
      field.type = 'hidden';
      field.name = 'draft';
      field.value = banner.dataset.draftId;
      form.appendChild(field);
    }, true);
  }
}());

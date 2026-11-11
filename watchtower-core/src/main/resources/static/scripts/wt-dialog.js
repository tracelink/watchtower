(() => {
 'use strict';
 // Shared dialogs (UAT walkthrough, 2026-10-16): a button with data-wt-dialog-open="#id" opens that
 // md-dialog, and data-wt-dialog-close inside a dialog closes it. Pages with their own dialog
 // scripts keep using data-wt-dialog-target. Installed once; the shell is swapped by htmx.
 if (window.watchtowerDialogInstalled) return;
 window.watchtowerDialogInstalled = true;
 // Type-to-confirm (destructive confirms): an input with data-wt-confirm-name="<name>" enables
 // the dialog's [data-wt-confirm-submit] button only while it holds that exact name. The server
 // checks the name too; this only keeps the button honest. Cleared whenever the dialog closes.
 const confirmButtons = field => {
  const scope = field.closest('md-dialog') || field.closest('form');
  return scope ? scope.querySelectorAll('[data-wt-confirm-submit]') : [];
 };
 const syncConfirm = field => {
  const expected = field.getAttribute('data-wt-confirm-name') || '';
  const typed = String(field.value || '').trim();
  confirmButtons(field).forEach(button => { button.disabled = expected === '' || typed !== expected; });
 };
 document.addEventListener('input', event => {
  const field = event.target instanceof Element ? event.target.closest('[data-wt-confirm-name]') : null;
  if (field) syncConfirm(field);
 });
 document.addEventListener('closed', event => {
  if (!(event.target instanceof Element)) return;
  event.target.querySelectorAll('[data-wt-confirm-name]').forEach(field => {
   field.value = '';
   syncConfirm(field);
  });
 }, true);
 window.watchtowerSyncConfirm = syncConfirm;
 document.addEventListener('click', event => {
  const close = event.target.closest('md-dialog [data-wt-dialog-close]');
  if (close) {
   close.closest('md-dialog').close();
   return;
  }
  const open = event.target.closest('[data-wt-dialog-open]');
  if (!open) return;
  const selector = open.getAttribute('data-wt-dialog-open');
  // Only ids, so a crafted attribute can't select arbitrary elements.
  if (!/^#[A-Za-z][\w-]*$/.test(selector)) return;
  const dialog = document.querySelector(selector);
  if (dialog && typeof dialog.show === 'function') dialog.show();
 });
})();

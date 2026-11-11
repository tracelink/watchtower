(() => {
 'use strict';
 if (window.watchtowerHelpInstalled) return;
 window.watchtowerHelpInstalled = true;
 // Focus opens help only when the person tabbed to it. A dialog moves focus to its first control
 // (often this (i)) when it opens; that must not pop the help open uninvited (UAT 2026-10-15).
 const KEYBOARD_FOCUS_MS = 600;
 let tabbedAt = 0;
 document.addEventListener('keydown', event => { if (event.key === 'Tab') tabbedAt = Date.now(); }, true);
 const MARGIN = 8;
 // Inside a dialog the help would be clipped by the dialog's scrolling box, so it is placed in
 // viewport coordinates next to its (i) instead.
 const place = help => {
  const body = help.querySelector('.wt-feature-help-body');
  if (!body) return;
  if (!help.open || !help.closest('md-dialog, dialog')) { body.classList.remove('wt-feature-help-body--fixed'); body.style.removeProperty('inset'); return; }
  body.classList.add('wt-feature-help-body--fixed');
  const anchor = help.querySelector('summary').getBoundingClientRect();
  const width = body.offsetWidth;
  const left = Math.max(MARGIN, Math.min(anchor.left, window.innerWidth - width - MARGIN));
  body.style.inset = (anchor.bottom + 4) + 'px auto auto ' + left + 'px';
 };
 document.addEventListener('toggle', event => {
  if (event.target instanceof HTMLDetailsElement && event.target.matches('.wt-feature-help')) place(event.target);
 }, true);
 document.addEventListener('pointerover', event => {
  if (event.pointerType === 'touch') return;
  const help = event.target.closest('.wt-feature-help');
  if (help && !help.contains(event.relatedTarget) && help.dataset.dismissed !== 'true') help.open = true;
 });
 document.addEventListener('pointerout', event => {
  const help = event.target.closest('.wt-feature-help');
  if (help && !help.contains(event.relatedTarget)) { delete help.dataset.dismissed; if (!help.contains(document.activeElement)) help.open = false; }
 });
 document.addEventListener('focusin', event => {
  const help = event.target.closest('.wt-feature-help');
  if (help && help.dataset.dismissed !== 'true' && Date.now() - tabbedAt < KEYBOARD_FOCUS_MS) help.open = true;
 });
 document.addEventListener('click', event => {
  const summary = event.target.closest('.wt-feature-help > summary');
  if (summary) { event.preventDefault();const help = summary.parentElement;delete help.dataset.dismissed;help.open = true;return; }
  if (!event.target.closest('[data-help-dismiss]')) return;
  const help = event.target.closest('.wt-feature-help');help.open = false;help.dataset.dismissed = 'true';help.querySelector('summary').focus();
 });
 document.addEventListener('keydown', event => {
  const help = event.target.closest('.wt-feature-help');
  if (help && event.key === 'Escape') { help.open = false;help.dataset.dismissed = 'true';help.querySelector('summary').focus(); }
 });
})();

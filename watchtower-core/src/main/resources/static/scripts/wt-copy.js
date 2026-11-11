(() => {
 'use strict';
 // Copy chips (UAT walkthrough, 2026-10-16): any button with data-copy-text copies that text and
 // says so in its hover text for a moment. Installed once; the shell is swapped by htmx.
 if (window.watchtowerCopyInstalled) return;
 window.watchtowerCopyInstalled = true;
 const CONFIRM_MS = 1500;
 const announce = (button, text) => {
  const original = button.getAttribute('data-tip');
  button.setAttribute('data-tip', text);
  button.setAttribute('aria-live', 'polite');
  window.setTimeout(() => {
   if (original === null) button.removeAttribute('data-tip'); else button.setAttribute('data-tip', original);
  }, CONFIRM_MS);
 };
 document.addEventListener('click', event => {
  const button = event.target.closest('[data-copy-text]');
  if (!button) return;
  const text = button.getAttribute('data-copy-text') || '';
  if (!text || !navigator.clipboard) {
   announce(button, 'Copy is not available here. Select the text and copy it manually.');
   return;
  }
  navigator.clipboard.writeText(text)
   .then(() => announce(button, 'Copied'))
   .catch(() => announce(button, 'Copy failed. Select the text and copy it manually.'));
 });
})();

(() => {
 'use strict';
 const form = document.getElementById('login_form');
 if (!form || form.dataset.enterBound) return;
 form.dataset.enterBound = 'true';
 form.addEventListener('keydown', event => {
  if (event.key !== 'Enter' || event.isComposing || event.keyCode === 229 || event.repeat ||
      event.defaultPrevented || !event.composedPath().some(node => node.id === 'inputPassword4')) return;
  event.preventDefault();
  form.requestSubmit();
 });
})();

/* PR settings: switches post their state with the form. A switch button flips aria-checked and the hidden field beside it. */
(function () {
  'use strict';
  document.addEventListener('click', function (event) {
    var toggle = event.target.closest('[data-switch]');
    if (!toggle) return;
    var on = toggle.getAttribute('aria-checked') !== 'true';
    toggle.setAttribute('aria-checked', String(on));
    var field = toggle.parentElement.querySelector('[data-switch-value]');
    if (field) field.value = String(on);
  });
})();

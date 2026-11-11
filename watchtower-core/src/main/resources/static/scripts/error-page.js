(function() {
  var back = document.querySelector('[data-error-back]');
  if (back) back.addEventListener('click', function() { window.history.back(); });
  var retry = document.querySelector('[data-error-retry]');
  if (retry) retry.addEventListener('click', function() { window.location.reload(); });
})();

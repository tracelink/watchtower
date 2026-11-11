(function () {
 'use strict';
 if (window.wtRuleHealthChipsInstalled) return;
 window.wtRuleHealthChipsInstalled = true;
 function healthChip(ruleId, chip) {
  var link = document.createElement('a');
  link.className = 'wt-mini-chip wt-meta-chip' + (chip.tone ? ' wt-mini-chip--' + chip.tone : '');
  link.href = '/rules/' + encodeURIComponent(ruleId) + '/health';
  link.setAttribute('data-tip', chip.tip + ' Opens Rule health.');
  link.setAttribute('aria-label', chip.text + '. ' + chip.tip + ' Opens Rule health.');
  var icon = document.createElement('span'); icon.className = 'material-icons'; icon.setAttribute('aria-hidden', 'true'); icon.textContent = chip.icon;
  var text = document.createElement('span'); text.textContent = chip.text;
  link.append(icon, text);
  return link;
 }
 function initialize() {
  document.querySelectorAll('[data-rule-health-chips]').forEach(async function (area) {
   if (area.dataset.ready) return; area.dataset.ready = 'true';
   try {
    var response = await fetch('/rule/evidence/' + area.dataset.ruleId + '/health');
    if (!response.ok) return;
    var result = await response.json(); if (!area.isConnected) return;
    area.replaceChildren();
    // Plain-word chips (Dev walk, 2026-10-22): "Too little data" in amber, the meaning on hover,
    // and a click opens Rule health.
    (result.header_chips || []).forEach(function (chip) { area.appendChild(healthChip(area.dataset.ruleId, chip)); });
   } catch (_) { /* The dedicated page provides a recoverable error; editing remains available. */ }
  });
 }
 document.addEventListener('DOMContentLoaded', initialize); document.addEventListener('htmx:afterSwap', initialize); initialize();
})();

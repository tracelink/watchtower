(function () {
  'use strict';
  if (window.wtFindingFeedbackNavigationInstalled) return;
  window.wtFindingFeedbackNavigationInstalled = true;
  var dialog;
  var requestNumber = 0;
  function reviewDialog() {
    if (dialog) return dialog;
    dialog = document.createElement('md-dialog');
    dialog.className = 'wt-dialog-wide wt-feedback-dialog';
    dialog.setAttribute('aria-label', 'Review finding');
    var headline = document.createElement('div'); headline.slot = 'headline'; headline.className = 'wt-dialog-headline';
    var title = document.createElement('span'); title.textContent = 'Review finding'; headline.appendChild(title);
    var close = document.createElement('button'); close.type = 'button'; close.className = 'wt-icon-action';
    close.setAttribute('aria-label', 'Close review'); close.setAttribute('data-wt-dialog-close', '');
    var icon = document.createElement('span'); icon.className = 'material-icons'; icon.setAttribute('aria-hidden', 'true'); icon.textContent = 'close';
    close.appendChild(icon); headline.appendChild(close); dialog.appendChild(headline);
    var content = document.createElement('div'); content.slot = 'content'; content.dataset.feedbackModalContent = '';
    dialog.appendChild(content); document.body.appendChild(dialog);
    dialog.addEventListener('closed', function () { requestNumber++; content.replaceChildren(); });
    dialog.addEventListener('click', function (event) {
      if (event.target.closest('.wt-review-actions a.wt-button-link-secondary')) {
        event.preventDefault(); dialog.close();
      }
    });
    return dialog;
  }
  async function openReview(url) {
    var modal = reviewDialog(); var content = modal.querySelector('[data-feedback-modal-content]');
    var mine = ++requestNumber; content.textContent = 'Loading review…'; modal.show();
    try {
      var response = await fetch(url, {credentials: 'same-origin', cache: 'no-store'});
      if (!response.ok) throw new Error('Review unavailable (' + response.status + ').');
      var page = new DOMParser().parseFromString(await response.text(), 'text/html');
      var review = page.querySelector('[data-feedback-page]');
      if (!review) throw new Error('Review form unavailable.');
      if (mine !== requestNumber || !modal.isConnected) return;
      content.replaceChildren(document.importNode(review, true));
      if (window.htmx) window.htmx.process(content);
      document.dispatchEvent(new Event('htmx:afterSwap'));
    } catch (error) {
      if (mine === requestNumber) content.textContent = error.message || 'Review unavailable.';
    }
  }
  function refresh() {
    var context = document.querySelector('[data-feedback-context]');
    if (!context) return;
    document.querySelectorAll('[data-feedback-open]').forEach(function (link) {
      var workspace = link.closest('[data-finding-workspace]');
      var item = workspace && workspace.querySelector('[data-finding-item].is-selected');
      if (!item || !item.dataset.feedbackKey) {
        link.removeAttribute('href'); link.setAttribute('aria-disabled', 'true'); return;
      }
      var back = new URL(window.location.href);
      back.searchParams.set('reviewFinding', item.dataset.feedbackKey);
      [['reviewSearch', '[data-finding-search]'], ['reviewSeverity', '[data-finding-severity]'], ['reviewLocation', '[data-finding-location]']].forEach(function (pair) {
        var field = workspace.querySelector(pair[1]);
        if (field && field.value) back.searchParams.set(pair[0], field.value); else back.searchParams.delete(pair[0]);
      });
      var params = new URLSearchParams({scanType: context.dataset.scanType, scanId: context.dataset.scanId,
        findingKey: item.dataset.feedbackKey, returnTo: back.pathname + back.search + back.hash});
      if (item.dataset.providerDetailUrl) {
        var provider = new URL(item.dataset.providerDetailUrl, window.location.origin);
        params.set('providerPage', provider.searchParams.get('page') || '0');
      }
      link.href = '/finding-feedback/review?' + params;
      link.removeAttribute('aria-disabled');
    });
  }
  ['DOMContentLoaded', 'htmx:afterSwap', 'wt:finding-selection', 'wt:finding-cleared'].forEach(function (event) { document.addEventListener(event, refresh); });
  document.addEventListener('input', function (event) { if (event.target.closest('[data-finding-workspace]')) refresh(); });
  document.addEventListener('change', function (event) { if (event.target.closest('[data-finding-workspace]')) refresh(); });
  document.addEventListener('click', function (event) {
    var link = event.target.closest('[data-feedback-open]');
    if (!link) return;
    refresh();
    if (!link.href || link.getAttribute('aria-disabled') === 'true') { event.preventDefault(); return; }
    event.preventDefault(); openReview(link.href);
  });
  document.addEventListener('wt:review-saved', function (event) {
    var result = event.detail || {};
    var states = {TRUE_POSITIVE: ['true', 'check_circle', 'Reviewed: true positive'],
      FALSE_POSITIVE: ['false', 'cancel', 'Reviewed: false positive'], UNKNOWN: ['unknown', 'help', 'Reviewed: unknown']};
    var state = states[result.judgment]; if (!state) return;
    document.querySelectorAll('[data-feedback-context]').forEach(function (context) {
      if (context.dataset.scanType !== result.scanType || context.dataset.scanId !== result.scanId) return;
      var keys = new Set(result.findingKeys || []);
      document.querySelectorAll('[data-finding-workspace] [data-finding-item]').forEach(function (item) {
        if (!keys.has(item.dataset.feedbackKey)) return;
        item.dataset.reviewState = state[0]; item.dataset.reviewIcon = state[1]; item.dataset.reviewLabel = state[2];
        var marker = item.querySelector('.wt-review-marker');
        if (marker) {
          marker.className = 'material-icons wt-review-marker wt-review-marker--' + state[0];
          marker.textContent = state[1]; marker.title = state[2]; marker.setAttribute('aria-label', state[2]);
        }
        if (item.classList.contains('is-selected')) {
          var chip = item.closest('[data-finding-workspace]').querySelector('[data-detail-review]');
          if (chip) {
            chip.hidden = false; chip.className = 'wt-mini-chip wt-review-chip--' + state[0];
            chip.querySelector('[data-detail-review-icon]').textContent = state[1];
            chip.querySelector('[data-detail-review-label]').textContent = state[2];
          }
        }
      });
    });
  });
  refresh();
})();

(function () {
  'use strict';
  // Sections (UAT walkthrough, 2026-10-16): the segmented control shows one section at a time.
  // Searching shows every section with a match; clearing the search returns to the chosen one.
  var DEFAULT_PANE = 'start-here';
  var activePane = DEFAULT_PANE;

  function guideRoot() {
    return document.querySelector('[data-feature-guide]');
  }

  function searching(guide) {
    var input = guide.querySelector('[data-feature-search]');
    return !!(input && input.value && input.value.trim() !== '');
  }

  function showPane(guide, id) {
    if (!guide.querySelector('[data-feature-pane]#' + id)) id = DEFAULT_PANE;
    activePane = id;
    guide.querySelectorAll('[data-feature-tab]').forEach(function (tab) {
      if (tab.getAttribute('data-feature-tab') === id) tab.setAttribute('aria-current', 'page');
      else tab.removeAttribute('aria-current');
    });
    if (searching(guide)) return;
    guide.querySelectorAll('[data-feature-pane]').forEach(function (pane) {
      pane.hidden = pane.id !== id;
    });
  }

  function revealTopic() {
    var guide = guideRoot();
    if (!guide) return;
    var target = window.location.hash ? document.getElementById(window.location.hash.slice(1)) : null;
    var pane = target ? target.closest('[data-feature-pane]') : null;
    showPane(guide, pane ? pane.id : activePane);
    if (target && target.matches('[data-feature-topic]')) {
      target.open = true;
      target.scrollIntoView({block: 'start'});
    }
  }

  // Guide search (UAT #7): show only topics whose text matches, open them, and hide empty sections.
  function filterTopics(input) {
    var guide = input.closest('[data-feature-guide]');
    var query = (input.value || '').trim().toLowerCase();
    var shown = 0;
    guide.querySelectorAll('[data-feature-topic]').forEach(function (topic) {
      var match = query === '' || topic.textContent.toLowerCase().indexOf(query) >= 0;
      topic.hidden = !match;
      if (match) shown += 1;
      if (query !== '') topic.open = match;
    });
    if (query === '') {
      showPane(guide, activePane);
    } else {
      guide.querySelectorAll('[data-feature-pane]').forEach(function (pane) {
        pane.hidden = !pane.matches('[data-feature-section]')
            || !pane.querySelector('[data-feature-topic]:not([hidden])');
      });
    }
    var status = guide.querySelector('[data-feature-search-status]');
    if (status) status.textContent = query === '' ? '' : shown + (shown === 1 ? ' topic matches' : ' topics match');
    var none = guide.querySelector('[data-feature-no-results]');
    if (none) none.hidden = query === '' || shown > 0;
  }

  document.addEventListener('click', function (event) {
    var tab = event.target.closest && event.target.closest('[data-feature-tab]');
    if (!tab) return;
    var guide = tab.closest('[data-feature-guide]');
    if (!guide) return;
    event.preventDefault();
    var input = guide.querySelector('[data-feature-search]');
    if (input && searching(guide)) {
      input.value = '';
      filterTopics(input);
    }
    showPane(guide, tab.getAttribute('data-feature-tab'));
    if (window.history && window.history.replaceState) {
      window.history.replaceState(null, '', '#' + tab.getAttribute('data-feature-tab'));
    }
  });
  document.addEventListener('input', function (event) {
    if (event.target.matches && event.target.matches('[data-feature-search]')) filterTopics(event.target);
  });
  document.addEventListener('submit', function (event) {
    if (event.target.matches && event.target.matches('[data-feature-search-form]')) event.preventDefault();
  });
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', revealTopic);
  else revealTopic();
  window.addEventListener('hashchange', revealTopic);
  document.addEventListener('htmx:afterSettle', revealTopic);
})();

(() => {
  'use strict';
  // The New scan form's Repository field (UAT walkthrough, 2026-10-16): as you type, it lists the
  // repositories Watchtower knows for the chosen integration; any other name can still be typed.
  const DEBOUNCE_MS = 200;
  const field = document.querySelector('[data-repo-suggest]');
  if (!field || field.dataset.repoSuggestReady === 'true') return;
  field.dataset.repoSuggestReady = 'true';
  const list = document.getElementById(field.dataset.repoSuggest);
  const form = field.closest('form');
  const integration = form ? form.querySelector('[name="apiLabel"]') : null;
  if (!list) return;
  let timer = null;
  let sequence = 0;

  const close = () => { list.hidden = true; };
  const choose = name => {
    field.value = name;
    close();
    field.focus();
  };
  const render = suggestions => {
    list.replaceChildren();
    suggestions.forEach(suggestion => {
      const option = document.createElement('button');
      option.type = 'button';
      option.className = 'wt-combo__option';
      option.setAttribute('role', 'option');
      const icon = document.createElement('span');
      icon.className = 'material-icons';
      icon.setAttribute('aria-hidden', 'true');
      icon.textContent = 'code';
      const name = document.createElement('strong');
      name.textContent = suggestion.name;
      const meta = document.createElement('span');
      meta.className = 'wt-combo__meta';
      meta.textContent = [suggestion.project, suggestion.status].filter(Boolean).join(' · ');
      option.append(icon, name, meta);
      option.addEventListener('click', () => choose(suggestion.name));
      list.append(option);
    });
    const hint = document.createElement('span');
    hint.className = 'wt-combo__hint';
    hint.textContent = suggestions.length
      ? 'Any other name still works.'
      : 'No known repository matches; the name you type is still used.';
    list.append(hint);
    list.hidden = false;
  };
  // A page can name its own same-origin list (data-repo-suggest-url, e.g. the secrets allowlist,
  // across every integration); otherwise the New scan list for the chosen integration.
  const ownUrl = /^\/[\w/-]+$/.test(field.dataset.repoSuggestUrl || '') ? field.dataset.repoSuggestUrl : null;
  const search = async () => {
    const apiLabel = integration ? integration.value : '';
    if (!ownUrl && !apiLabel) { close(); return; }
    const url = ownUrl
      ? ownUrl + '?q=' + encodeURIComponent(field.value || '')
      : '/scan/repositories?apiLabel=' + encodeURIComponent(apiLabel) + '&q=' + encodeURIComponent(field.value || '');
    const mine = ++sequence;
    try {
      const response = await fetch(url, {headers: {Accept: 'application/json'}});
      if (!response.ok) throw new Error('Repository list unavailable');
      const suggestions = await response.json();
      if (mine === sequence) render(Array.isArray(suggestions) ? suggestions : []);
    } catch (error) {
      if (mine === sequence) close();
    }
  };
  const schedule = () => {
    window.clearTimeout(timer);
    timer = window.setTimeout(search, DEBOUNCE_MS);
  };
  field.addEventListener('input', schedule);
  field.addEventListener('focus', schedule);
  field.addEventListener('keydown', event => {
    if (event.key === 'Escape') close();
    if (event.key === 'ArrowDown' && !list.hidden) {
      const first = list.querySelector('[role="option"]');
      if (first) { event.preventDefault(); first.focus(); }
    }
  });
  list.addEventListener('keydown', event => {
    const options = Array.from(list.querySelectorAll('[role="option"]'));
    const index = options.indexOf(document.activeElement);
    if (event.key === 'Escape') { close(); field.focus(); }
    if (event.key === 'ArrowDown' && index >= 0) { event.preventDefault(); (options[index + 1] || options[index]).focus(); }
    if (event.key === 'ArrowUp' && index >= 0) { event.preventDefault(); (index === 0 ? field : options[index - 1]).focus(); }
  });
  document.addEventListener('click', event => {
    if (!list.hidden && !list.contains(event.target) && event.target !== field) close();
  });
  if (integration) integration.addEventListener('change', () => { if (!list.hidden) schedule(); });
})();

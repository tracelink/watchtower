(() => {
  const region = document.querySelector('[data-log-region]');
  const linesContainer = document.querySelector('[data-log-lines]');
  const search = document.querySelector('[data-log-filter]');
  const severity = document.querySelector('[data-log-severity]');
  const pause = document.querySelector('[data-log-pause]');
  const refresh = document.querySelector('[data-log-refresh]');
  const status = document.querySelector('[data-log-status]');
  const filterStatus = document.querySelector('[data-log-filter-status]');
  if (!region || !linesContainer || !search || !severity || !pause || !refresh) return;
  const statusText = status?.querySelector('[data-log-status-text]') || status;
  const pauseLabel = pause.querySelector('[data-log-pause-label]') || pause;
  const pauseIcon = pause.querySelector('[slot="icon"]');

  let paused = false;
  let level = 'all';
  const setStatus = (text, live) => {
    if (statusText) statusText.textContent = text;
    status?.classList.toggle('wt-mini-chip--ok', live);
  };
  // The logger's full name (hover text) is searchable too, not only the short name shown.
  const searchableText = line => {
    const logger = line.querySelector('.wt-log-line__logger');
    return `${line.textContent} ${logger?.dataset.tip || ''}`.toLocaleLowerCase();
  };
  const applyFilters = () => {
    const query = search.value.trim().toLocaleLowerCase();
    const lines = Array.from(linesContainer.querySelectorAll('[data-log-line]'));
    let shown = 0;
    lines.forEach(line => {
      const matchesText = !query || searchableText(line).includes(query);
      const matchesLevel = level === 'all' || line.dataset.level === level;
      line.hidden = !(matchesText && matchesLevel);
      if (!line.hidden) shown += 1;
    });
    if (filterStatus) {
      filterStatus.textContent = shown === lines.length ? '' : `${shown} of ${lines.length} lines`;
    }
  };

  const loadLogs = async () => {
    if (paused) return;
    const wasNearBottom = region.scrollHeight - region.scrollTop - region.clientHeight < 32;
    const previousScrollTop = region.scrollTop;
    const lineLimit = document.querySelector('[name="lines"]')?.value || '200';
    try {
      const response = await fetch(`/logging?lines=${encodeURIComponent(lineLimit)}`, {
        headers: {'Accept': 'text/html'}
      });
      if (!response.ok) throw new Error(`Refresh failed (${response.status})`);
      const parsed = new DOMParser().parseFromString(await response.text(), 'text/html');
      const replacement = parsed.querySelector('[data-log-lines]');
      if (!replacement) throw new Error('Refresh response did not contain logs');
      linesContainer.replaceChildren(...Array.from(replacement.children, child => child.cloneNode(true)));
      applyFilters();
      region.scrollTop = wasNearBottom ? region.scrollHeight : previousScrollTop;
      setStatus('Live', true);
      status?.setAttribute('data-tip', `Refreshed at ${new Date().toLocaleTimeString()}; new lines load every 15 seconds`);
    } catch (error) {
      setStatus(error.message, false);
    }
  };

  search.addEventListener('input', applyFilters);
  severity.querySelectorAll('[data-log-level-filter]').forEach(button => {
    button.addEventListener('click', () => {
      level = button.dataset.logLevelFilter;
      severity.querySelectorAll('[data-log-level-filter]').forEach(other =>
        other.setAttribute('aria-pressed', String(other === button)));
      applyFilters();
    });
  });
  refresh.addEventListener('click', loadLogs);
  // Changing how many lines to load reloads at once; there is no Apply button.
  document.querySelector('[name="lines"]')?.addEventListener('change', loadLogs);
  pause.addEventListener('click', () => {
    paused = !paused;
    pause.setAttribute('aria-pressed', String(paused));
    pauseLabel.textContent = paused ? 'Resume' : 'Pause';
    if (pauseIcon) pauseIcon.textContent = paused ? 'play_arrow' : 'pause';
    setStatus(paused ? 'Paused' : 'Live', !paused);
    if (!paused) loadLogs();
  });
  const refreshTimer = setInterval(() => {
    if (!region.isConnected) {
      clearInterval(refreshTimer);
      return;
    }
    loadLogs();
  }, 15000);
  const stopOnNavigation = event => {
    if (event.detail?.target?.id !== 'content') return;
    clearInterval(refreshTimer);
    document.removeEventListener('htmx:beforeSwap', stopOnNavigation);
  };
  document.addEventListener('htmx:beforeSwap', stopOnNavigation);
  applyFilters();
})();

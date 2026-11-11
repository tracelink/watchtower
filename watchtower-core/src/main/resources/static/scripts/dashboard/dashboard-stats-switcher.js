(() => {
  document.querySelectorAll('[data-dashboard-tabs]').forEach(tablist => {
    if (tablist.dataset.dashboardTabsReady === 'true') return;
    tablist.dataset.dashboardTabsReady = 'true';
    const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));
    const activate = (tab, moveFocus) => {
      tabs.forEach(candidate => {
        const selected = candidate === tab;
        candidate.setAttribute('aria-selected', String(selected));
        candidate.tabIndex = selected ? 0 : -1;
        const panel = document.getElementById(candidate.getAttribute('aria-controls'));
        if (panel) panel.hidden = !selected;
      });
      if (moveFocus) tab.focus();
    };
    tabs.forEach((tab, index) => {
      tab.addEventListener('click', () => activate(tab, false));
      tab.addEventListener('keydown', event => {
        let target;
        if (event.key === 'ArrowRight') target = tabs[(index + 1) % tabs.length];
        if (event.key === 'ArrowLeft') target = tabs[(index - 1 + tabs.length) % tabs.length];
        if (event.key === 'Home') target = tabs[0];
        if (event.key === 'End') target = tabs[tabs.length - 1];
        if (!target) return;
        event.preventDefault();
        activate(target, true);
      });
    });
  });
})();

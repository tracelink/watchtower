(() => {
  'use strict';
  const installed = window.watchtowerWebhooksInstalled;
  if (installed) { installed(); return; }

  const PAGE_SIZE = 20;
  const OUTCOME_PAGE_SIZE = 50;
  const MAX_SELECTION = 500;
  const MAX_SEARCH = 255;
  const ALL_EVENTS = ['pullrequest:created', 'pullrequest:updated', 'pullrequest:fulfilled', 'pullrequest:rejected', 'pullrequest:comment_created'];
  const PRESETS = {
    ALL: { icon: 'notifications_active', label: 'All events', tip: 'Opened, updated, merged, declined and commented', events: ALL_EVENTS },
    SCAN_AND_CLOSE: { icon: 'task_alt', label: 'Scan & close', tip: 'Opened, updated, merged and declined', events: ALL_EVENTS.slice(0, 4) },
    SCAN_ONLY: { icon: 'manage_search', label: 'Scan only', tip: 'Opened and updated', events: ALL_EVENTS.slice(0, 2) }
  };
  const ERRORS = {
    MISSING_WEBHOOK_PERMISSION: 'No permission',
    CREDENTIALS_REJECTED: 'Credentials rejected',
    NOT_FOUND: 'Not found',
    LIMIT: '50-hook limit reached',
    RATE_LIMITED: 'Rate limited',
    ERROR: 'Request failed',
    INTERRUPTED: 'Interrupted; retry the failed items',
    CONFIGURATION_CHANGED: 'Integration changed; start a new operation',
    SELECTION_OR_OWNERSHIP_CHANGED: 'Selection or ownership changed'
  };
  const OUTCOMES = { CHECKED: 'Checked', CREATED: 'Created', UPDATED: 'Updated', UNCHANGED: 'Unchanged', DELETED: 'Deleted', ROTATED: 'Rotated' };
  const ACTIONS = {
    SYNC: { icon: 'sync', title: 'Refresh' },
    UPSERT: { icon: 'tune', title: 'Add or change hooks' },
    DELETE: { icon: 'delete', title: 'Delete hook' },
    ROTATE: { icon: 'key', title: 'Rotate signing secret' }
  };
  const RETRYABLE = ['PARTIAL_FAILURE', 'QUEUE_FAILED'];
  const RUNNING = ['QUEUED', 'RUNNING'];

  const errorText = code => ERRORS[code] || code;
  const presetOf = events => Object.keys(PRESETS).find(key => {
    const wanted = PRESETS[key].events;
    return events.length === wanted.length && wanted.every(event => events.includes(event));
  });
  const plainEvents = events => events.map(event => event.replace('pullrequest:', '').replace(/_/g, ' ')).join(', ');

  function node(tag, text, cls) {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = text;
    if (cls) element.className = cls;
    return element;
  }
  function icon(name, cls) { const element = node('span', name, 'material-icons' + (cls ? ' ' + cls : '')); element.setAttribute('aria-hidden', 'true'); return element; }
  function withTip(element, tip) { if (tip) element.setAttribute('data-tip', tip); return element; }
  function chip(text, tone, iconName, tip) {
    const element = node('span', undefined, 'wt-status-chip wt-tone-' + (tone || 'neutral'));
    if (iconName) element.append(icon(iconName));
    element.append(document.createTextNode(text));
    return withTip(element, tip);
  }
  function miniChip(text, iconName, tip) {
    const element = node('span', undefined, 'wt-mini-chip');
    if (iconName) element.append(icon(iconName, 'wt-webhook-chip-icon'), document.createTextNode(' '));
    element.append(document.createTextNode(text));
    return withTip(element, tip);
  }
  function dot(active) {
    const wrapper = node('span');
    wrapper.append(withTip(node('span', undefined, 'wt-dot ' + (active ? 'wt-dot--ready' : 'wt-dot--off')), active ? 'Active' : 'Paused'),
      node('span', active ? 'Active' : 'Paused', 'visually-hidden'));
    return wrapper;
  }
  function eventsChip(hook) {
    const preset = presetOf(hook.events);
    if (preset) return miniChip(PRESETS[preset].label, PRESETS[preset].icon, PRESETS[preset].tip);
    return miniChip(hook.events.length + (hook.events.length === 1 ? ' event' : ' events'), 'webhook', plainEvents(hook.events));
  }
  function ownerChip(hook) {
    return hook.owned
      ? chip('Watchtower', 'success', 'verified_user')
      : chip('Foreign', 'neutral', 'lock', 'Not created by Watchtower, so it can’t be changed here');
  }
  function ago(at) {
    if (!at) return 'Never checked';
    const minutes = Math.max(0, Math.round((Date.now() - at) / 60000));
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return minutes + ' min ago';
    if (minutes < 1440) return Math.round(minutes / 60) + ' h ago';
    const days = Math.round(minutes / 1440);
    return days + (days === 1 ? ' day ago' : ' days ago');
  }
  function whenNode(at, cls) { return withTip(node('span', ago(at), cls || 'wt-webhook-when'), at ? new Date(at).toLocaleString() : 'Not checked yet'); }

  function wire() {
    document.querySelectorAll('[data-webhook-page]:not([data-webhook-wired])').forEach(page => {
      page.dataset.webhookWired = 'true';
      const $ = selector => page.querySelector(selector);
      const base = page.dataset.endpoint;
      const canModify = page.dataset.canModify === 'true';
      const status = $('[data-webhook-status]');
      const selected = new Set();
      let inventory, repoPage = 0, repoSearch = '', pickerPage = 0, pickerSearch = '', pickerData;
      let settingsTarget, deleteTarget, pollTimer, noticeTimer, searchTimer, outcomeId, outcomePage = 0;
      let inventoryRequest = 0, pickerRequest = 0;

      function message(text, error) {
        clearTimeout(noticeTimer);
        status.textContent = text || '';
        status.hidden = !text;
        status.classList.toggle('wt-tone-danger', !!error);
        if (text && !error) noticeTimer = setTimeout(() => message(''), 6000);
      }
      async function request(path = '', method = 'GET', body) {
        const headers = { Accept: 'application/json' };
        if (method !== 'GET') { headers['Content-Type'] = 'application/json'; headers[page.dataset.csrfHeader] = page.dataset.csrfToken; }
        const response = await fetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body), cache: 'no-store' });
        const data = await response.json();
        if (!response.ok) throw new Error(data.message || errorText(data.code) || 'Webhook request failed');
        return data;
      }
      function iconButton(label, iconName, handler, danger) {
        const button = node('button', undefined, 'wt-icon-action' + (danger ? ' wt-icon-action--danger' : ''));
        button.type = 'button';
        button.setAttribute('aria-label', label);
        button.setAttribute('data-tip', label);
        button.append(icon(iconName));
        button.addEventListener('click', handler);
        return button;
      }
      function open(dialog) { if (!dialog.open) dialog.show(); }
      function close(dialog) { dialog.close(); }
      async function command(path, method, body, dialog) {
        const buttons = [...page.querySelectorAll('md-filled-button')];
        buttons.forEach(button => { button.disabled = true; });
        try {
          const data = await request(path, method, body);
          if (dialog) close(dialog);
          message('Queued. You can leave this page.');
          await load();
          schedule();
          return data;
        } catch (e) {
          await load();
          message(e.message, true);
          throw e;
        } finally {
          buttons.forEach(button => { button.disabled = false; });
          updateSelection();
        }
      }
      const refresh = repository => command('/refresh', 'POST', repository ? { repository } : {}).catch(() => {});

      function settings(scope, hook) {
        settingsTarget = { scope, hook };
        $('[data-settings-title]').textContent = (scope || 'Workspace') + ' · events';
        const preset = (hook && presetOf(hook.events)) || 'ALL';
        page.querySelectorAll('[data-settings-form] input[name="preset"]').forEach(radio => { radio.checked = radio.value === preset; });
        $('[data-settings-active]').checked = hook ? hook.active : true;
        open($('[data-hook-settings]'));
      }
      async function liveSettings(scope, hook) {
        try {
          message('Checking the current hook settings…');
          const hooks = await request(scope ? '/repos/' + encodeURIComponent(scope) + '/live' : '/workspace/live');
          const current = hooks.find(candidate => candidate.uuid === hook.uuid);
          if (!current || !current.owned) throw new Error('This hook is missing or no longer owned. Refresh and try again.');
          message('');
          settings(scope, current);
        } catch (e) { message(e.message, true); }
      }
      function remove(scope, hook) {
        deleteTarget = { scope, hook };
        $('[data-delete-description]').textContent = (scope || 'Workspace') + ' — this removes only this hook.';
        open($('[data-hook-delete]'));
      }
      function togglePaused(scope, hook) {
        const preset = presetOf(hook.events);
        if (!preset) { liveSettings(scope, hook); return; }
        const path = scope ? '/repos/' + encodeURIComponent(scope) + '/' + encodeURIComponent(hook.uuid) : '/workspace';
        command(path, scope ? 'PATCH' : 'PUT', { preset, active: !hook.active, uuid: hook.uuid }).catch(() => {});
      }
      function hookActions(parent, scope, hook) {
        if (!hook.owned) {
          const lock = withTip(node('span', undefined, 'wt-icon-action'), 'Foreign hook · read only');
          lock.append(icon('lock'));
          parent.append(lock);
          return;
        }
        if (!canModify) return;
        const name = scope || 'workspace';
        parent.append(
          iconButton('Edit ' + name + ' hook', 'edit', () => liveSettings(scope, hook)),
          iconButton((hook.active ? 'Pause ' : 'Resume ') + name + ' hook', hook.active ? 'pause_circle' : 'play_circle', () => togglePaused(scope, hook)),
          iconButton('Delete ' + name + ' hook', 'delete', () => remove(scope, hook), true));
      }
      function statusChip(scope, hook, activeWorkspace) {
        if (scope.error) return chip(errorText(scope.error), 'danger', 'key_off', 'The last good result is kept' + (scope.checkedAt ? ' (' + ago(scope.checkedAt) + ')' : ''));
        if (scope.stale) return chip('Stale', 'warning', 'schedule', 'Not checked for over 24 hours');
        if (hook.owned && !hook.secretSet) return chip('Secret missing', 'danger', 'key_off', 'This hook has no signing secret, so deliveries are refused');
        if (hook.owned && hook.active && activeWorkspace) return chip('Also on workspace', 'warning', 'content_copy', 'The workspace hook covers this repository too, so each event can arrive twice');
        return null;
      }

      function renderChips(data, ownedWorkspace, activeWorkspace) {
        const repos = data.ownedRepositoryHookCount;
        const parts = [];
        if (ownedWorkspace.length) parts.push('Workspace');
        if (repos) parts.push(repos + (repos === 1 ? ' repo' : ' repos'));
        const known = data.workspace.checkedAt || data.total > 0;
        const brand = miniChip('Bitbucket Cloud');
        brand.classList.add('wt-meta-chip');
        const chips = [brand];
        chips.push(parts.length
          ? chip(parts.join(' + '), 'success', 'webhook', 'The workspace hook plus the repository hooks Watchtower knows about')
          : chip(known ? 'No Watchtower hooks' : 'Coverage unknown', 'neutral', 'webhook', known ? 'Choose repositories or add a workspace hook' : 'Refresh to check Bitbucket'));
        if (activeWorkspace && repos > 0) chips.push(chip('Duplicate coverage', 'warning', 'content_copy', 'Active workspace and repository hooks can send the same event twice'));
        if (data.rotation.pending) {
          const tip = 'Some hooks still use the old key. Retry the failed items before ' + new Date(data.rotation.previousAcceptedUntil).toLocaleString() + '.';
          const rotation = chip('Rotation incomplete', 'danger', 'key_off', tip);
          if (canModify) {
            const button = node('button', undefined, rotation.className);
            button.type = 'button';
            button.setAttribute('data-tip', tip);
            button.append(...rotation.childNodes);
            button.onclick = () => command('/jobs/' + encodeURIComponent(data.rotation.operationId) + '/retry', 'POST').catch(() => {});
            chips.push(button);
          } else chips.push(rotation);
        }
        const latest = data.operations[0];
        const activity = node('button', undefined, 'wt-mini-chip wt-meta-chip');
        activity.type = 'button';
        activity.setAttribute('data-activity-open', '');
        activity.setAttribute('data-tip', 'Recent refreshes and changes');
        activity.append(icon('history', 'wt-webhook-chip-icon'), document.createTextNode(' Activity ' + data.operations.length));
        if (latest && (latest.failed > 0 || RETRYABLE.includes(latest.status))) activity.append(document.createTextNode(' '), node('span', undefined, 'wt-dot wt-dot--setup'));
        activity.onclick = openActivity;
        chips.push(activity);
        const info = node('details', undefined, 'wt-popover');
        const summary = node('summary', undefined, 'wt-icon-action');
        summary.setAttribute('aria-label', 'How webhooks work');
        summary.append(icon('info'));
        const body = node('div', 'Foreign hooks are read only. Refresh reads Bitbucket for the catalog’s repositories. Repository hooks work next to the workspace hook.', 'wt-popover__body');
        info.append(summary, body);
        chips.push(info);
        $('[data-webhook-chips]').replaceChildren(...chips);
      }

      function workspaceRow(scope, hook, first) {
        const row = node('div', undefined, 'wt-webhook-ws');
        const tile = node('span', undefined, 'wt-scanner-tile' + (hook && hook.owned ? ' wt-scanner-tile--ran' : ''));
        tile.append(icon('domain'));
        const main = node('div', undefined, 'wt-webhook-ws__main');
        main.append(node('strong', 'Workspace'));
        if (hook) {
          main.append(dot(hook.active), hook.owned ? eventsChip(hook) : ownerChip(hook), node('span', hook.urlHostPath, 'wt-webhook-path'));
          if (hook.owned && !hook.secretSet) main.append(chip('Secret missing', 'danger', 'key_off', 'This hook has no signing secret, so deliveries are refused'));
        } else {
          main.append(node('span', scope.checkedAt ? 'No hook' : 'Not checked yet', 'wt-muted'));
        }
        if (first && scope.error) main.append(chip(errorText(scope.error), 'danger', 'key_off', 'The last good result is kept'));
        else if (first && scope.stale) main.append(chip('Stale', 'warning', 'schedule', 'Not checked for over 24 hours'));
        row.append(tile, main);
        if (first) row.append(whenNode(scope.checkedAt), iconButton('Refresh workspace', 'refresh', () => command('/refresh', 'POST', { workspaceOnly: true }).catch(() => {})));
        if (hook) {
          const actions = node('div', undefined, 'wt-webhook-actions');
          hookActions(actions, '', hook);
          row.append(actions);
        } else if (canModify) {
          const add = node('md-outlined-button');
          add.setAttribute('has-icon', '');
          add.setAttribute('data-workspace-add', '');
          const plus = icon('add');
          plus.setAttribute('slot', 'icon');
          add.append(plus, document.createTextNode('Add workspace hook'));
          add.onclick = () => settings('', null);
          row.append(add);
        }
        return row;
      }

      function repositoryRow(scope, hook, activeWorkspace) {
        const tr = node('tr');
        const name = node('th', scope.scope, 'fw-semibold');
        name.setAttribute('scope', 'row');
        tr.append(name);
        if (hook) {
          const events = node('td'); events.append(eventsChip(hook));
          const owner = node('td'); owner.append(ownerChip(hook));
          const active = node('td'); active.append(dot(hook.active));
          tr.append(events, owner, active);
        } else {
          for (let i = 0; i < 3; i++) tr.append(node('td', '—', 'wt-muted'));
        }
        const state = node('td');
        const flag = hook ? statusChip(scope, hook, activeWorkspace)
          : scope.error ? chip(errorText(scope.error), 'danger', 'key_off', 'The last good result is kept')
            : chip(scope.checkedAt ? 'No hooks' : 'Not checked', 'neutral', scope.checkedAt ? 'link_off' : 'schedule');
        if (flag) state.append(flag);
        const checked = node('td'); checked.append(whenNode(scope.checkedAt, 'wt-muted'));
        const actions = node('td', undefined, 'wt-webhook-actions');
        if (hook) hookActions(actions, scope.scope, hook);
        if (!hook || scope.error || scope.stale) actions.append(iconButton('Refresh ' + scope.scope, 'refresh', () => refresh(scope.scope)));
        if (!hook && canModify) actions.append(iconButton('Add hook for ' + scope.scope, 'add', () => settings(scope.scope, null)));
        tr.append(state, checked, actions);
        return tr;
      }

      function render(data) {
        inventory = data;
        const workspace = data.workspace;
        const ownedWorkspace = workspace.hooks.filter(hook => hook.owned);
        const activeWorkspace = ownedWorkspace.some(hook => hook.active);
        renderChips(data, ownedWorkspace, activeWorkspace);
        $('[data-workspace-hooks]').replaceChildren(...(workspace.hooks.length
          ? workspace.hooks.map((hook, index) => workspaceRow(workspace, hook, index === 0))
          : [workspaceRow(workspace, null, true)]));
        const rows = [];
        data.repositories.forEach(scope => {
          if (!scope.hooks.length) rows.push(repositoryRow(scope, null, activeWorkspace));
          else scope.hooks.forEach(hook => rows.push(repositoryRow(scope, hook, activeWorkspace)));
        });
        if (!rows.length) {
          const tr = node('tr'), td = node('td');
          td.colSpan = 7;
          const empty = node('div', data.total ? 'Nothing matches.' : 'No repository hooks yet. Choose repositories to add one.', 'wt-webhook-empty');
          empty.prepend(icon('webhook'));
          td.append(empty); tr.append(td); rows.push(tr);
        }
        $('[data-repo-hooks]').replaceChildren(...rows);
        const from = repoPage * PAGE_SIZE + 1, to = Math.min(data.total, (repoPage + 1) * PAGE_SIZE);
        $('[data-repo-page-label]').textContent = data.total ? from + '–' + to + ' of ' + data.total : '';
        $('[data-repo-prev]').disabled = repoPage === 0;
        $('[data-repo-next]').disabled = (repoPage + 1) * PAGE_SIZE >= data.total;
        renderActivity(data.operations);
      }

      function resultChip(op) {
        if (op.status === 'DONE') return chip('Done', 'success', 'check_circle');
        if (RETRYABLE.includes(op.status)) return chip(op.failed ? op.failed + ' failed' : 'Failed', 'warning', 'warning');
        if (RUNNING.includes(op.status)) return chip('Running', 'info', 'schedule');
        return chip(op.status, 'neutral');
      }
      function renderActivity(operations) {
        const rows = operations.map(op => {
          const meta = ACTIONS[op.action] || { icon: 'history', title: op.action };
          const row = node('div', undefined, 'wt-webhook-activity-row');
          const text = node('div', undefined, 'wt-webhook-activity-row__text');
          text.append(node('strong', meta.title), node('small', (op.actor || 'system') + ' · ' + ago(op.createdAt)));
          row.append(icon(meta.icon), text, resultChip(op), node('small', op.finished + ' of ' + op.total));
          if (canModify && RETRYABLE.includes(op.status)) row.append(iconButton('Retry failed items', 'replay', () => command('/jobs/' + op.id + '/retry', 'POST').catch(() => {})));
          row.append(iconButton('View results', 'chevron_right', () => showOutcomes(op.id, 0)));
          return row;
        });
        if (!rows.length) {
          const empty = node('div', 'Nothing has run yet.', 'wt-webhook-empty');
          empty.prepend(icon('history'));
          rows.push(empty);
        }
        $('[data-activity-list]').replaceChildren(...rows);
      }
      function showActivityList() {
        $('[data-activity-list]').hidden = false;
        $('[data-activity-detail]').hidden = true;
        $('[data-outcome-back]').hidden = true;
      }
      function openActivity() { showActivityList(); open($('[data-webhook-activity]')); }
      async function showOutcomes(id, pageNumber) {
        try {
          const op = await request('/jobs/' + encodeURIComponent(id) + '?page=' + pageNumber);
          outcomeId = id; outcomePage = pageNumber;
          $('[data-outcome-summary]').textContent = (ACTIONS[op.action] || { title: op.action }).title + ' · ' + op.finished + ' of ' + op.total + ' done · ' + op.failed + ' failed';
          $('[data-outcome-list]').replaceChildren(...op.tasks.map(task => {
            const line = node('div', undefined, 'wt-webhook-outcome');
            const state = task.status === 'DONE' ? 'ready' : task.status === 'FAILED' ? 'setup' : 'info';
            line.append(node('span', undefined, 'wt-dot wt-dot--' + state), node('span', (task.scope || 'Workspace') + ' — ' + (OUTCOMES[task.result] || errorText(task.result) || 'Waiting')));
            return line;
          }));
          $('[data-outcome-prev]').disabled = pageNumber === 0;
          $('[data-outcome-next]').disabled = (pageNumber + 1) * OUTCOME_PAGE_SIZE >= op.total;
          $('[data-activity-list]').hidden = true;
          $('[data-activity-detail]').hidden = false;
          $('[data-outcome-back]').hidden = false;
          open($('[data-webhook-activity]'));
        } catch (e) { message(e.message, true); }
      }

      async function load() {
        const generation = ++inventoryRequest;
        try {
          const data = await request('?q=' + encodeURIComponent(repoSearch) + '&page=' + repoPage);
          if (!page.isConnected || generation !== inventoryRequest) return;
          render(data);
          schedule();
        } catch (e) { message(e.message, true); }
      }
      function schedule() {
        clearTimeout(pollTimer);
        if (!page.isConnected) return;
        if (inventory && inventory.operations.some(op => RUNNING.includes(op.status))) pollTimer = setTimeout(load, 2000);
      }

      function updateSelection() {
        $('[data-picker-count]').textContent = selected.size + ' selected';
        $('[data-picker-save]').disabled = selected.size === 0;
      }
      async function picker() {
        const generation = ++pickerRequest;
        try {
          const data = await request('/repositories?q=' + encodeURIComponent(pickerSearch) + '&page=' + pickerPage);
          if (generation !== pickerRequest) return;
          pickerData = data;
          const rows = data.content.map(repo => {
            const label = node('label');
            const input = document.createElement('input');
            input.type = 'checkbox';
            input.checked = selected.has(repo.slug);
            input.setAttribute('aria-label', 'Select ' + repo.slug);
            input.addEventListener('change', () => {
              if (input.checked) {
                if (selected.size >= MAX_SELECTION) { input.checked = false; message('Select up to ' + MAX_SELECTION + ' repositories per operation.', true); return; }
                selected.add(repo.slug);
              } else selected.delete(repo.slug);
              updateSelection();
            });
            label.append(input, node('span', repo.slug, 'wt-webhook-name'));
            if (repo.paused) label.append(miniChip('Scanning paused', undefined, 'Scanning is paused; a hook does not change that'));
            return label;
          });
          $('[data-picker-list]').replaceChildren(...(rows.length ? rows : [node('div', 'No enabled repositories match. Sync the Code Repos catalog if needed.', 'wt-webhook-empty')]));
          $('[data-picker-page]').textContent = 'Page ' + (pickerPage + 1);
          $('[data-picker-prev]').disabled = pickerPage === 0;
          $('[data-picker-next]').disabled = data.last;
          updateSelection();
        } catch (e) { message(e.message, true); }
      }

      $('[data-webhook-refresh]').onclick = () => refresh();
      $('[data-repo-prev]').onclick = () => { repoPage--; load(); };
      $('[data-repo-next]').onclick = () => { repoPage++; load(); };
      $('[data-repo-search]').oninput = e => { clearTimeout(searchTimer); searchTimer = setTimeout(() => { repoSearch = (e.target.value || '').slice(0, MAX_SEARCH); repoPage = 0; load(); }, 200); };
      $('[data-picker-search]').oninput = e => { clearTimeout(searchTimer); searchTimer = setTimeout(() => { pickerSearch = (e.target.value || '').slice(0, MAX_SEARCH); pickerPage = 0; picker(); }, 200); };
      $('[data-picker-prev]').onclick = () => { pickerPage--; picker(); };
      $('[data-picker-next]').onclick = () => { pickerPage++; picker(); };
      $('[data-picker-select]').onclick = () => { (pickerData?.content || []).forEach(repo => { if (selected.size < MAX_SELECTION) selected.add(repo.slug); }); picker(); };
      $('[data-picker-clear]').onclick = () => { selected.clear(); picker(); };
      $('[data-outcome-prev]').onclick = () => showOutcomes(outcomeId, outcomePage - 1);
      $('[data-outcome-next]').onclick = () => showOutcomes(outcomeId, outcomePage + 1);
      $('[data-outcome-back]').onclick = showActivityList;
      [['[data-settings-cancel]', '[data-hook-settings]'], ['[data-picker-cancel]', '[data-repo-picker]'], ['[data-delete-cancel]', '[data-hook-delete]'],
        ['[data-rotation-cancel]', '[data-secret-rotation]'], ['[data-activity-close]', '[data-webhook-activity]']].forEach(([button, dialog]) => { $(button).onclick = () => close($(dialog)); });

      if (canModify) {
        $('[data-webhook-choose]').onclick = () => { open($('[data-repo-picker]')); picker(); };
        $('[data-settings-save]').onclick = () => {
          const { scope, hook } = settingsTarget;
          const body = { preset: page.querySelector('[data-settings-form] input[name="preset"]:checked').value, active: $('[data-settings-active]').checked, uuid: hook?.uuid };
          const path = scope ? (hook ? '/repos/' + encodeURIComponent(scope) + '/' + encodeURIComponent(hook.uuid) : '/repos') : '/workspace';
          command(path, scope ? (hook ? 'PATCH' : 'POST') : 'PUT', scope && !hook ? { ...body, repositories: [scope] } : body, $('[data-hook-settings]')).catch(() => {});
        };
        $('[data-delete-confirm]').onclick = () => {
          const { scope, hook } = deleteTarget;
          command(scope ? '/repos/' + encodeURIComponent(scope) + '/' + encodeURIComponent(hook.uuid) : '/workspace?uuid=' + encodeURIComponent(hook.uuid), 'DELETE', undefined, $('[data-hook-delete]')).catch(() => {});
        };
        $('[data-picker-save]').onclick = () => command('/repos', 'POST', {
          repositories: [...selected].sort(),
          preset: page.querySelector('input[name="pickerPreset"]:checked').value,
          active: $('[data-picker-active]').checked
        }, $('[data-repo-picker]')).then(() => { selected.clear(); updateSelection(); }).catch(() => {});
        const rotationField = $('[data-rotation-confirmation]');
        rotationField.setAttribute('label', 'Type ' + page.dataset.label + ' to confirm');
        $('[data-webhook-rotate]').onclick = () => {
          const menu = $('.wt-webhook-more'); if (menu) menu.open = false;
          open($('[data-secret-rotation]'));
          rotationField.value = '';
          $('[data-rotation-start]').disabled = true;
        };
        rotationField.oninput = e => { $('[data-rotation-start]').disabled = e.target.value !== page.dataset.label; };
        $('[data-rotation-start]').onclick = () => command('/rotate-secret', 'POST', { confirmLabel: rotationField.value }, $('[data-secret-rotation]')).catch(() => {});
      }
      load();
    });
  }
  window.watchtowerWebhooksInstalled = wire;
  wire();
  document.addEventListener('htmx:afterSwap', wire);
})();

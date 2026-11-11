(function () {
  'use strict';

  const rows = document.querySelector('[data-advisory-rows]');
  const status = document.querySelector('[data-advisory-status]');
  const dialog = document.querySelector('#saveAdvisoryRuleDialog');
  const advisoryName = document.querySelector('#advisoryName');
  const cancel = document.querySelector('#cancelSaveAdvisoryRuleDialog');

  if (!rows || !status || !dialog || !advisoryName) {
    return;
  }

  function addCell(row, value) {
    const cell = document.createElement('td');
    cell.textContent = value == null || value === '' ? '—' : String(value);
    row.appendChild(cell);
    return cell;
  }

  function safeReference(uri) {
    try {
      const url = new URL(uri);
      return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null;
    } catch (error) {
      return null;
    }
  }

  // CVSS bands as the image report colours them (CvssText): critical, high, medium, low, none.
  function cvssBand(score) {
    const value = Number(score);
    if (score == null || score === '' || Number.isNaN(value)) {
      return {key: 'UNKNOWN', label: 'No CVSS', tip: 'The advisory has no CVSS score'};
    }
    const band = value >= 9 ? ['CRITICAL', 'critical'] : value >= 7 ? ['1', 'high']
      : value >= 4 ? ['3', 'medium'] : value > 0 ? ['5', 'low'] : ['6', 'none'];
    return {key: band[0], label: String(score), tip: 'CVSS ' + score + ': ' + band[1]};
  }

  function icon(name) {
    const glyph = document.createElement('span');
    glyph.className = 'material-icons';
    glyph.setAttribute('aria-hidden', 'true');
    glyph.textContent = name;
    return glyph;
  }

  function messageRow(text) {
    const row = document.createElement('tr');
    const cell = addCell(row, text);
    cell.colSpan = 4;
    return row;
  }

  // The advisory ID is the link to its reference (when it is a web address); one row per advisory.
  function renderAdvisories(advisories) {
    rows.replaceChildren();
    if (advisories.length === 0) {
      rows.appendChild(messageRow('No advisories match these filters.'));
      return;
    }

    advisories.forEach(function (advisory) {
      const row = document.createElement('tr');
      const idCell = document.createElement('th');
      idCell.scope = 'row';
      const reference = safeReference(advisory.uri);
      if (reference) {
        const link = document.createElement('a');
        link.href = reference;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.className = 'wt-advisory-link';
        link.append(document.createTextNode(advisory.advisoryName || '—'), icon('open_in_new'));
        link.setAttribute('aria-label', (advisory.advisoryName || 'Advisory') + ' (opens the advisory)');
        idCell.appendChild(link);
      } else {
        idCell.textContent = advisory.advisoryName || '—';
      }
      row.appendChild(idCell);

      const scoreCell = document.createElement('td');
      const band = cvssBand(advisory.score);
      const chip = document.createElement('span');
      chip.className = 'wt-sev wt-cvss-chip wt-sev-' + band.key;
      chip.tabIndex = 0;
      chip.dataset.tip = band.tip;
      chip.textContent = band.label;
      scoreCell.appendChild(chip);
      row.appendChild(scoreCell);

      addCell(row, advisory.description);

      const actionCell = document.createElement('td');
      actionCell.className = 'text-end';
      const action = document.createElement('button');
      action.type = 'button';
      action.className = 'wt-icon-action';
      action.dataset.advisoryAllow = '';
      action.dataset.tip = 'Ignore advisory';
      action.setAttribute('aria-label', 'Ignore ' + (advisory.advisoryName || 'advisory'));
      action.appendChild(icon('playlist_remove'));
      action.addEventListener('click', function () {
        advisoryName.value = advisory.advisoryName;
        const label = document.querySelector('[data-advisory-name-label]');
        if (label) {
          label.textContent = advisory.advisoryName;
        }
        const score = document.querySelector('[data-advisory-score-label]');
        if (score) {
          score.textContent = band.key === 'UNKNOWN' ? 'No CVSS score' : 'Score ' + band.label;
        }
        dialog.show();
      });
      actionCell.appendChild(action);
      row.appendChild(actionCell);
      rows.appendChild(row);
    });
  }

  // Server-side search and paging (UAT #24): only one page of advisories is loaded at a time.
  const filters = document.querySelector('[data-advisory-filters]');
  const previous = document.querySelector('[data-advisory-previous]');
  const next = document.querySelector('[data-advisory-next]');
  const PAGE_SIZE = 25;
  let page = 0;

  function filterValue(selector, fallback) {
    const element = document.querySelector(selector);
    return element && element.value ? element.value : fallback;
  }

  function load() {
    const params = new URLSearchParams({
      search: filterValue('[data-advisory-search]', ''),
      minScore: filterValue('[data-advisory-min-score]', '0'),
      sort: filterValue('[data-advisory-sort]', 'score'),
      page: String(page),
      size: String(PAGE_SIZE)
    });
    status.textContent = 'Loading advisories…';
    return fetch('/rest/advisory/search?' + params.toString(), {headers: {'Accept': 'application/json'}})
      .then(function (response) {
        if (!response.ok) {
          throw new Error('Advisories could not be loaded.');
        }
        return response.json();
      })
      .then(function (payload) {
        const advisories = Array.isArray(payload.advisories) ? payload.advisories : [];
        const total = Number(payload.total) || 0;
        renderAdvisories(advisories);
        const first = total === 0 ? 0 : page * PAGE_SIZE + 1;
        const last = Math.min(total, page * PAGE_SIZE + PAGE_SIZE);
        status.textContent = total === 0 ? 'No advisories match these filters.'
          : first + '–' + last + ' of ' + total + (total === 1 ? ' advisory' : ' advisories');
        if (previous) previous.disabled = page === 0;
        if (next) next.disabled = last >= total;
        // Previous/Next only when there is more than one page.
        const actions = previous && previous.closest('.wt-pagination__actions');
        if (actions) actions.hidden = total <= PAGE_SIZE;
      })
      .catch(function () {
        rows.replaceChildren(messageRow('Advisories could not be loaded. Try again later.'));
        status.textContent = 'Advisories could not be loaded.';
      });
  }

  // The score and sort chips apply at once; the search applies as you type (after a pause) or on Enter.
  function reload() {
    page = 0;
    load();
  }
  if (filters) {
    filters.addEventListener('submit', function (event) {
      event.preventDefault();
      reload();
    });
    filters.addEventListener('change', function (event) {
      if (event.target.matches('[data-advisory-min-score], [data-advisory-sort]')) {
        reload();
      }
    });
    let typing = null;
    filters.addEventListener('input', function (event) {
      if (!event.target.matches('[data-advisory-search]')) {
        return;
      }
      clearTimeout(typing);
      typing = setTimeout(reload, 350);
    });
  }
  if (previous) {
    previous.addEventListener('click', function () {
      if (page > 0) { page -= 1; load(); }
    });
  }
  if (next) {
    next.addEventListener('click', function () { page += 1; load(); });
  }
  load();

  if (cancel) {
    cancel.addEventListener('click', function () {
      dialog.close();
    });
  }
}());

(function () {
  'use strict';
  // Rules → Knowledge (UAT #23). Entries are server-rendered with names; this script handles the
  // decision buttons and the searchable pickers that replace typed repository, rule and evidence IDs.
  var SEARCH_DELAY_MS = 250;
  var root = document.querySelector('[data-knowledge-page]');
  if (!root) return;

  // One line on the page and one in the proposal dialog, so a refused proposal is seen there.
  function status(message) {
    root.querySelectorAll('[data-knowledge-status]').forEach(function (line) {
      line.textContent = message;
      // The dialog's line sits above a scrolling form; bring it into view so an answer or a refusal is not missed.
      if (message && line.closest('md-dialog') && typeof line.scrollIntoView === 'function') line.scrollIntoView({block: 'nearest'});
    });
  }

  // A Material select that upgraded before its options were parsed reads as empty although one is marked selected,
  // so the evidence search would ask for no type at all. Give such a select the value it declares.
  root.querySelectorAll('md-outlined-select[value]').forEach(function (select) {
    if (!select.value) select.value = select.getAttribute('value');
  });

  // A link from a rule or review prefills the proposal; open the dialog once it is upgraded.
  var proposeDialog = root.querySelector('[data-knowledge-propose][data-open-on-load]');
  if (proposeDialog) {
    var openProposal = function () { if (typeof proposeDialog.show === 'function') proposeDialog.show(); };
    if (window.customElements && typeof window.customElements.whenDefined === 'function') {
      window.customElements.whenDefined('md-dialog').then(openProposal);
    } else {
      openProposal();
    }
  }

  var PROPOSED_URL = '/rules/knowledge?status=PROPOSED';

  /** Only two fixed destinations: this page reloaded, or the proposals list. */
  function navigate(toProposals) {
    if (typeof window.WatchtowerKnowledgeNavigate === 'function') window.WatchtowerKnowledgeNavigate(toProposals ? PROPOSED_URL : 'reload');
    else if (toProposals) window.location.assign(PROPOSED_URL);
    else window.location.reload();
  }

  /** JSON request; POSTs carry the CSRF header. Server error messages are shown as written. */
  async function api(url, data) {
    var options = {headers: {'Content-Type': 'application/json'}};
    if (data !== undefined) {
      options.method = 'POST';
      options.headers[root.dataset.csrfHeader] = root.dataset.csrfToken;
      options.body = JSON.stringify(data);
    }
    var response = await fetch(url, options);
    var body = {};
    try { body = await response.json(); } catch (e) { body = {}; }
    if (!response.ok) throw new Error(body.error || body.message || 'Knowledge is unavailable (' + response.status + ').');
    return body;
  }

  // --- Decisions ---

  async function decide(button) {
    var verb = button.dataset.knowledgeDecision;
    var note = null;
    if (verb === 'reject') note = window.prompt('Why reject this proposal? (optional)') || null;
    if (verb === 'retire') {
      note = window.prompt('Why retire this entry?');
      if (!note) return;
    }
    await api('/rule/knowledge/' + encodeURIComponent(button.dataset.id) + '/' + verb,
      {version: Number(button.dataset.version), note: note});
    status(verb === 'approve' ? 'Approved.' : verb === 'reject' ? 'Rejected.' : 'Retired.');
    navigate(false);
  }

  // --- Pickers ---

  function picker(name) { return root.querySelector('[data-knowledge-picker="' + name + '"]'); }

  function chosen(name) {
    var list = picker(name);
    return list ? Array.from(list.querySelectorAll('[data-picker-selected] li')) : [];
  }

  // The icon on a chosen chip: the kind of evidence, or what the picker chooses.
  var PICKER_ICONS = {review: 'rate_review', finding_feedback: 'fact_check', missed_case: 'bug_report', repositories: 'folder', rules: 'rule'};

  function icon(name) {
    var mark = document.createElement('span');
    mark.className = 'material-icons';
    mark.setAttribute('aria-hidden', 'true');
    mark.textContent = name;
    return mark;
  }

  /** A chosen item as a chip with a remove icon; the chip is the list item the proposal reads. */
  function selectedItem(label, value, type, iconName) {
    var item = document.createElement('li');
    item.className = 'wt-mini-chip';
    item.dataset.pickerValue = value;
    if (type) item.dataset.pickerType = type;
    var text = document.createElement('span');
    text.textContent = label;
    var remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'wt-chip-remove';
    remove.dataset.pickerRemove = '';
    remove.setAttribute('aria-label', 'Remove ' + label);
    remove.appendChild(icon('close'));
    item.append(icon(iconName), text, remove);
    return item;
  }

  function renderResults(fieldset, options, type) {
    var results = fieldset.querySelector('[data-picker-results]');
    results.replaceChildren();
    if (!options.length) {
      var none = document.createElement('li');
      none.textContent = 'No matches.';
      results.appendChild(none);
      return;
    }
    options.forEach(function (option) {
      var item = document.createElement('li');
      var label = document.createElement('span');
      label.textContent = option.label;
      if (option.preview) {
        var preview = document.createElement('span');
        preview.className = 'wt-page-meta';
        preview.textContent = ' ' + option.preview;
        label.appendChild(preview);
      }
      var add = document.createElement('button');
      add.type = 'button';
      add.className = 'wt-icon-action';
      add.dataset.tip = 'Add';
      add.setAttribute('aria-label', 'Add ' + option.label);
      add.appendChild(icon('add'));
      add.addEventListener('click', function () {
        var selected = fieldset.querySelector('[data-picker-selected]');
        var duplicate = Array.from(selected.children).some(function (li) {
          return li.dataset.pickerValue === option.id && (li.dataset.pickerType || '') === (type || '');
        });
        if (!duplicate) selected.appendChild(selectedItem(option.label, option.id, type, PICKER_ICONS[type || fieldset.dataset.knowledgePicker]));
        results.replaceChildren();
        scopeSummary();
      });
      item.append(label, add);
      results.appendChild(item);
    });
  }

  async function search(fieldset) {
    var name = fieldset.dataset.knowledgePicker;
    var typeSelect = fieldset.querySelector('[data-picker-type]');
    var kind = name === 'evidence' ? typeSelect.value : name;
    var params = new URLSearchParams({search: fieldset.querySelector('[data-picker-search]').value});
    // Evidence must belong to the chosen rules, so only offer theirs.
    if (name === 'evidence') chosen('rules').forEach(function (li) { params.append('ruleIds', li.dataset.pickerValue); });
    var page = await api('/rules/knowledge/options/' + encodeURIComponent(kind) + '?' + params.toString());
    renderResults(fieldset, page.content || [], name === 'evidence' ? kind : null);
  }

  var timers = new WeakMap();
  root.addEventListener('input', function (event) {
    var fieldset = event.target.closest('[data-knowledge-picker]');
    if (!fieldset || !event.target.matches('[data-picker-search]')) return;
    clearTimeout(timers.get(fieldset));
    timers.set(fieldset, setTimeout(function () {
      search(fieldset).catch(function (e) { status(e.message); });
    }, SEARCH_DELAY_MS));
  });

  // --- Proposal ---

  function value(name) { return root.querySelector('[data-knowledge-' + name + ']').value; }

  function plural(count, one, many) { return count + ' ' + (count === 1 ? one : many); }

  /** The "Limit the scope" line says what is set while it is closed, and warns while no repository is chosen. */
  function scopeSummary() {
    var summary = root.querySelector('[data-knowledge-scope-summary]');
    if (!summary) return;
    var all = root.querySelector('[data-knowledge-all-repositories]').checked;
    var repositories = chosen('repositories').length;
    var rules = chosen('rules').length;
    var cwes = value('cwes').split(',').filter(function (c) { return c.trim(); }).length;
    var parts = [];
    if (all) parts.push('All repositories');
    else if (repositories) parts.push(plural(repositories, 'repository', 'repositories'));
    if (rules) parts.push(plural(rules, 'rule', 'rules'));
    if (cwes) parts.push(plural(cwes, 'CWE', 'CWEs'));
    summary.textContent = parts.length ? parts.join(' · ') : 'Choose repositories';
    summary.classList.toggle('wt-tone-warning', !all && repositories === 0);
  }

  async function propose(event) {
    event.preventDefault();
    var body = {
      kind: value('kind'), statement: value('statement').trim(), language: value('language').trim(),
      library: value('library').trim(), versionRange: value('versions').trim(),
      allRepositories: root.querySelector('[data-knowledge-all-repositories]').checked,
      repositoryIds: chosen('repositories').map(function (li) { return Number(li.dataset.pickerValue); }),
      ruleIds: chosen('rules').map(function (li) { return Number(li.dataset.pickerValue); }),
      cwes: value('cwes').split(',').map(function (c) { return c.trim(); }).filter(Boolean),
      evidence: chosen('evidence').map(function (li) { return {type: li.dataset.pickerType, id: li.dataset.pickerValue}; }),
      reviewBy: value('review-by') || null
    };
    await api('/rule/knowledge', body);
    status('Proposed. Another person with Rule Modify must approve it before the assistant can cite it.');
    navigate(true);
  }

  root.addEventListener('click', function (event) {
    var decision = event.target.closest('[data-knowledge-decision]');
    if (decision) { decide(decision).catch(function (e) { status(e.message); }); return; }
    var remove = event.target.closest('[data-picker-remove]');
    if (remove) { remove.closest('li').remove(); scopeSummary(); }
  });
  root.addEventListener('change', scopeSummary);
  root.addEventListener('input', scopeSummary);
  scopeSummary();
  root.addEventListener('submit', function (event) {
    if (event.target.closest('[data-knowledge-form]')) propose(event).catch(function (e) { status(e.message); });
  });
})();

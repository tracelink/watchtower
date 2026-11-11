(function () {
 'use strict';
 // AiChat board (2026-10-22): the assistant is a right side panel. It shows what page it is
 // looking at, the model as one chip, starter questions, cited-rule chips, Helpful / Not helpful /
 // Copy on each answer, and an approval card for each ruleset change set a turn prepared. Every
 // server gate is unchanged: change sets are applied only by the explicit Approve and apply call.
 var CONTEXT_LIMIT = 300;
 var CONTEXT_PATTERN = /^\[Looking at: ([^\]\n]{1,320})\]\n\n/;
 var MINUTE = 60000;
 var REFRESH_DELAY = 120;
 // A page that re-renders itself on a timer asks again only when the question changed or this long has passed.
 var CONTEXT_REUSE_MS = 60000;
 var STARTERS = {
  ruleset: {title: 'Ask about this ruleset', items: [['trending_up', 'Which rules here are noisiest?'], ['account_tree', 'Explain the Included rulesets']],
   actions: [['playlist_add', 'Add a ruleset to a repository']]},
  rule: {title: 'Ask about this rule', items: [['help_outline', 'Explain what this rule finds'], ['trending_up', 'Is this rule noisy?'], ['tune', 'How could this rule be more precise?']]},
  report: {title: 'Ask about this scan', items: [['priority_high', 'Which findings should I look at first?'], ['help_outline', 'Explain the top finding']]},
  repository: {title: 'Ask about this repository', items: [['trending_up', 'Which rules find the most here?'], ['rule', 'Which ruleset does it use?']]},
  any: {title: 'Ask about rules and findings', items: [['trending_up', 'Which rules are noisiest?'], ['rule', 'How do rulesets work here?']]}
 };
 function text(parent, tag, value) { var el = document.createElement(tag); el.textContent = value; if (parent) parent.appendChild(el); return el; }
 function icon(parent, name) { var el = text(parent, 'span', name); el.className = 'material-icons'; el.setAttribute('aria-hidden', 'true'); return el; }
 function chip(parent, tag, iconName, label, tone, tip) {
  var el = document.createElement(tag); el.className = 'wt-mini-chip' + (tone ? ' wt-mini-chip--' + tone : '');
  if (iconName) icon(el, iconName); el.appendChild(document.createTextNode(label));
  if (tip) { el.setAttribute('data-tip', tip); if (tag === 'span') el.tabIndex = 0; }
  parent.appendChild(el); return el;
 }
 function iconButton(parent, iconName, label) {
  var b = document.createElement('button'); b.type = 'button'; b.className = 'wt-icon-action'; b.setAttribute('aria-label', label); b.setAttribute('data-tip', label);
  icon(b, iconName); parent.appendChild(b); return b;
 }
 function shortWhen(value) { return window.WatchtowerTime && window.WatchtowerTime.short ? window.WatchtowerTime.short(value) : when(value); }
 function when(value) { return window.WatchtowerTime ? window.WatchtowerTime.format(value) : new Date(value).toLocaleString(undefined, {timeZoneName: 'short'}); }
 /** "$0.00" for spend; whole-dollar caps read "$2". */
 function dollars(micros, whole) { var value = Math.max(0, Number(micros) || 0) / 1e6; return '$' + (whole && Number.isInteger(value) ? String(value) : value.toFixed(2)); }
 function plural(n, one, many) { return n + ' ' + (n === 1 ? one : many); }
 /** Safe link: http(s) only, no credentials; relative links must stay on this site. */
 function link(label, href) {
  try {
   var url = new URL(href, location.origin);
   if ((url.protocol === 'https:' || url.protocol === 'http:') && !url.username && !url.password && (href.startsWith('http') || url.origin === location.origin)) {
    var a = document.createElement('a'); a.textContent = label; a.href = href; a.rel = 'noopener noreferrer'; return a;
   }
  } catch (e) { }
  return document.createTextNode('[' + label + '](' + href + ')');
 }
 /** **bold**, `code` and [links](url) inside one line, built as nodes (never HTML). */
 function inline(parent, value) {
  var pattern = /\*\*([^*\n]{1,400})\*\*|`([^`\n]{1,400})`|\[([^\]\n]{1,200})\]\(([^\s)]{1,1000})\)/g; var last = 0; var m;
  while ((m = pattern.exec(value))) {
   parent.appendChild(document.createTextNode(value.slice(last, m.index)));
   if (m[1] !== undefined) text(parent, 'strong', m[1]);
   else if (m[2] !== undefined) text(parent, 'code', m[2]);
   else parent.appendChild(link(m[3], m[4]));
   last = pattern.lastIndex;
  }
  parent.appendChild(document.createTextNode(value.slice(last)));
 }
 /** The model's Markdown as readable text: paragraphs, bullet and numbered lists, headings, code blocks. */
 function markdown(parent, value) {
  var lines = String(value || '').replace(/\r\n?/g, '\n').split('\n'); var list = null; var para = null; var code = null;
  function flush() { list = null; para = null; }
  lines.forEach(function (raw) {
   if (/^\s*```/.test(raw)) { if (code) { code = null; } else { flush(); var pre = document.createElement('pre'); code = text(pre, 'code', ''); parent.appendChild(pre); } return; }
   if (code) { code.textContent += (code.textContent ? '\n' : '') + raw; return; }
   var line = raw.trim();
   if (!line) { flush(); return; }
   var heading = /^#{1,6}\s+(.*)$/.exec(line);
   if (heading) { flush(); var h = document.createElement('p'); h.className = 'wt-assistant-heading'; inline(h, heading[1]); parent.appendChild(h); return; }
   var bullet = /^[-*•]\s+(.*)$/.exec(line); var numbered = /^(\d{1,3})[.)]\s+(.*)$/.exec(line);
   if (bullet || numbered) {
    var tag = bullet ? 'ul' : 'ol';
    if (!list || list.tagName.toLowerCase() !== tag) { para = null; list = document.createElement(tag); parent.appendChild(list); }
    inline(text(list, 'li', ''), bullet ? bullet[1] : numbered[2]); return;
   }
   if (list && /^\s{2,}/.test(raw)) { var item = list.lastElementChild; item.appendChild(document.createTextNode(' ')); inline(item, line); return; }
   list = null;
   if (!para) { para = document.createElement('p'); parent.appendChild(para); } else para.appendChild(document.createElement('br'));
   inline(para, line);
  });
 }
 /** What the page is about: an explicit subject, the chosen ruleset, else the page title. */
 function pageSubject(trigger) {
  var content = document.getElementById('content') || document.body;
  var explicit = trigger && trigger.dataset.assistantSubject || (content.querySelector('[data-assistant-subject]') || {dataset: {}}).dataset.assistantSubject;
  if (explicit) return explicit;
  var ruleset = content.querySelector('[data-ruleset-link][aria-current="true"] span');
  if (ruleset && ruleset.textContent.trim()) return ruleset.textContent.trim();
  var title = content.querySelector('.page-title, h1');
  return title && title.textContent.trim() ? title.textContent.trim() : (document.title || 'This page');
 }
 function pageKind() {
  var p = location.pathname;
  if (/^\/rulesets?\b/.test(p)) return 'ruleset';
  if (/^\/rules?\//.test(p)) return 'rule';
  if (/report|scanreport/.test(p)) return 'report';
  if (/^\/repositories\/\d/.test(p)) return 'repository';
  return 'any';
 }
 /** The finding chosen in a report's findings list, named by its scan and key (ids only). */
 function selectedFinding(content) {
  var item = content.querySelector('[data-finding-item].is-selected[data-feedback-key]');
  var scope = content.querySelector('[data-scan-type][data-scan-id]');
  if (!item || !scope || !/^(pull_request|repository)$/.test(scope.dataset.scanType)) return null;
  // An AWS Security Agent finding is kept apart from the scan report the server rebuilds findings from, so it can never be found there.
  if (item.dataset.scannerGroup === 'aws') return null;
  var scanId = Number(scope.dataset.scanId);
  if (!Number.isInteger(scanId) || scanId < 1 || !item.dataset.feedbackKey) return null;
  return {v: 1, kind: 'finding', ids: {scanType: scope.dataset.scanType, scanId: scanId, findingKey: item.dataset.feedbackKey}, label: item.dataset.title || null};
 }
 /**
  * The ids of the page's subject, for the server to rebuild the context from: a kind and numbers or keys,
  * never text. A page or button names its subject with data-assistant-kind and data-assistant-* ids.
  */
 function pageIds(trigger) {
  var content = document.getElementById('content') || document.body;
  var source = trigger && trigger.dataset.assistantKind ? trigger : null;
  if (!source) { var found = selectedFinding(content); if (found) return found; source = content.querySelector('[data-assistant-kind]'); }
  if (!source) return null;
  var d = source.dataset, ids = {};
  function number(value) { var n = Number(value); return Number.isInteger(n) && n > 0 ? n : null; }
  if (d.assistantScanType) ids.scanType = d.assistantScanType;
  if (number(d.assistantScanId)) ids.scanId = number(d.assistantScanId);
  if (d.assistantFindingKey) ids.findingKey = d.assistantFindingKey;
  if (number(d.assistantRepoId)) ids.repoId = number(d.assistantRepoId);
  if (number(d.assistantRuleId)) ids.ruleId = number(d.assistantRuleId);
  return {v: 1, kind: d.assistantKind, ids: ids};
 }
 function clip(value) { return String(value || '').replace(/[\[\]\n\r]+/g, ' ').trim().slice(0, CONTEXT_LIMIT); }

 class AssistantDrawer extends HTMLElement {
  connectedCallback() {
   if (this.ready) return; this.ready = true;
   this.session = null; this.turn = null; this.timer = null; this.busy = false; this.historyOffset = 0; this.pendingSubmit = null; this.shownTurn = null;
   this.panel = this.querySelector('[data-assistant-panel]'); if (!this.panel) return;
   this.status = this.querySelector('[data-assistant-status]'); this.messages = this.querySelector('[data-assistant-messages]');
   this.form = this.querySelector('[data-assistant-form]'); this.input = this.querySelector('textarea');
   this.model = this.querySelector('[data-assistant-model]'); this.effort = this.querySelector('[data-assistant-effort]');
   this.context = null; this.contextRemoved = false;
   this.form.addEventListener('submit', e => { e.preventDefault(); this.submit(); });
   this.input.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); this.submit(); } });
   this.querySelector('[data-assistant-close]').addEventListener('click', () => this.close());
   this.querySelector('[data-assistant-cancel]').addEventListener('click', () => this.cancel());
   this.querySelector('[data-assistant-new]').addEventListener('click', () => this.newChat());
   this.querySelector('[data-assistant-history]').addEventListener('click', () => { var list = this.querySelector('[data-assistant-history-list]'); if (!list.hidden) { list.hidden = true; return; } this.historyOffset = 0; this.history(); });
   this.querySelector('[data-assistant-context-remove]').addEventListener('click', () => { this.contextRemoved = true; this.showContext(); });
   document.addEventListener('keydown', e => { if (e.key === 'Escape' && !this.panel.hidden && this.panel.contains(document.activeElement)) this.close(); });
   // Boosted navigation swaps #content only; the panel stays and follows the new page.
   // Share my draft: the designer's text goes with the next question only (the chip says so, with a way to stop).
   this.draftOn = false;
   document.addEventListener('wt:assistant-draft', e => { this.draftOn = !!(e.detail && e.detail.on); this.showDraft(); });
   this.querySelector('[data-assistant-draft-remove]').addEventListener('click', () => this.clearDraft());
   document.body.addEventListener('htmx:afterSettle', () => { if (this.draftOn) this.clearDraft(); });
   document.body.addEventListener('htmx:afterSettle', () => { if (!this.panel.hidden && !this.contextRemoved) { this.context = this.pageContext(); this.showContext(); this.refreshContext(); this.starters(); } });
   // Choosing another finding in a report moves the chip to it, without touching the chat.
   document.addEventListener('wt:finding-selected', () => { if (!this.panel.hidden && !this.contextRemoved) { this.context = this.pageContext(); this.showContext(); this.refreshContext(); } });
  }
  disconnectedCallback() { clearTimeout(this.timer); this.stopStream(); }
  async api(path, options) {
   options = options || {}; options.headers = Object.assign({'Content-Type': 'application/json'}, options.headers || {});
   if (options.method && options.method !== 'GET') options.headers[this.dataset.csrfHeader] = this.dataset.csrfToken;
   var response = await fetch(path, options);
   // An ended session redirects to the sign-in page; reading that as JSON gave a raw parse error
   var type = response.headers && response.headers.get ? response.headers.get('content-type') || '' : 'application/json';
   if (response.ok && (/\/login/.test(response.url || '') || /text\/html/.test(type))) { var ended = new Error('Your session has ended. Sign in again to keep using the assistant.'); ended.status = 401; throw ended; }
   if (!response.ok) { var data; try { data = await response.json(); } catch (e) { } var error = new Error((data && (data.error || data.message)) || 'Request unavailable (' + response.status + ').'); error.status = response.status; throw error; }
   return response.json();
  }
  availability(ready, problem, message) {
   this.available = ready; var setup = this.querySelector('[data-assistant-setup]');
   setup.hidden = ready; setup.setAttribute('data-tip', message || 'Chat is not available.'); setup.setAttribute('aria-label', message || 'Chat is not available.');
   this.querySelector('[data-assistant-setup-label]').textContent = problem === 'CHAT_OFF' ? 'Chat is off' : 'Chat needs setup';
   this.querySelector('.wt-assistant-toolbar').hidden = !ready; this.querySelector('[data-assistant-chips]').hidden = !ready; this.form.hidden = !ready;
   this.querySelector('[data-assistant-intro]').hidden = ready; var settings = this.querySelector('[data-assistant-settings]'); if (settings) settings.hidden = ready;
   this.messages.hidden = !ready;
   if (!ready) { this.querySelector('[data-assistant-history-list]').hidden = true; this.querySelector('[data-assistant-start]').hidden = true; }
   else this.starters();
  }
  async checkReady() { var s = await this.api('/assistant/status'); this.availability(s.ready, s.problem, s.message); return s.ready; }
  /** Opens the panel; a trigger's context sentence becomes the hidden page context, never the message. */
  async open(prompt, trigger, opener) {
   this.opener = opener || trigger || null; this.panel.hidden = false; document.body.classList.add('wt-assistant-open');
   var detail = trigger && trigger.dataset.assistantContext ? trigger.dataset.assistantContext : null;
   if (trigger) this.contextRemoved = false;
   if (!this.contextRemoved) this.context = {label: pageSubject(trigger), detail: detail, request: pageIds(trigger), fromButton: !!(trigger && trigger.dataset.assistantKind)};
   this.showContext();
   this.availability(false, null, 'Checking chat setup.'); this.status.textContent = '';
   try {
    if (!(await this.checkReady())) return;
    if (!this.models) {
     var data = await this.api('/assistant/models'); this.models = data.models; this.retentionDays = data.retentionDays; this.rulesetActions = data.rulesetActions === true; this.contextCards = data.contextCards === true; this.showDraft();
     this.model.value = data.defaultModel; this.effort.value = data.defaultEffort; this.modelMenu(); this.modes();
     var active = await this.api('/assistant/active'); if (active.length) await this.reopen(active[0].session_id);
    }
    this.starters(); await this.budget(); await this.refreshContext();
    if (prompt) this.input.value = prompt;
    this.input.focus();
   } catch (e) { this.availability(false, null, e.message); this.status.textContent = e.message; }
  }
  close() {
   this.panel.hidden = true; document.body.classList.remove('wt-assistant-open');
   var back = this.opener && this.opener.isConnected ? this.opener : document.querySelector('.wt-assistant-launcher'); if (back) back.focus();
  }
  newChat() {
   if (this.busy) { this.status.textContent = 'Stop or finish the current answer first.'; return; }
   this.stopStream(); this.session = null; this.turn = null; this.pendingSubmit = null; this.shownTurn = null;
   this.messages.replaceChildren(); this.status.textContent = ''; this.querySelector('[data-assistant-history-list]').hidden = true;
   var expiry = this.querySelector('[data-assistant-expiry]'); expiry.textContent = ''; expiry.hidden = true; this.starters();
  }
  showDraft() { this.querySelector('[data-assistant-draft-chip]').hidden = !(this.draftOn && this.contextCards); }
  clearDraft() { this.draftOn = false; this.showDraft(); document.dispatchEvent(new CustomEvent('wt:assistant-draft-cleared')); }
  /** The designer's text for this one question, or null when there is nothing to share. */
  draftText() {
   if (!this.draftOn || !this.contextCards || !window.WatchtowerAiHelpers) return null;
   var value = window.WatchtowerAiHelpers.collectDraft(); return value ? value : null;
  }
  /** A refused draft says why in one chip and one sentence; nothing was sent. */
  draftRefused(message) {
   var section = text(this.messages, 'section', ''); section.className = 'wt-assistant-message wt-assistant-message--assistant';
   var row = text(section, 'div', ''); row.className = 'wt-assistant-cited'; chip(row, 'span', 'lock', 'Draft not shared', 'bad', 'Nothing was sent to the AI.');
   text(section, 'span', message).className = 'wt-assistant-note';
   this.messages.scrollTop = this.messages.scrollHeight;
  }
  /** The page as it is now; a button that named its own subject keeps it while the person moves through findings. */
  pageContext() {
   if (this.context && this.context.fromButton) return this.context;
   return {label: pageSubject(null), detail: null, request: pageIds(null), fromButton: false};
  }
  /** Asks the server how it understands the page; the chip shows its answer, never page text. */
  refreshContext() {
   // Moving quickly through findings asks once, for where the person stops; a replaced wait is released, never left hanging.
   clearTimeout(this.contextTimer);
   if (this.contextDone) this.contextDone();
   return new Promise(resolve => {
    this.contextDone = resolve;
    this.contextTimer = setTimeout(() => { this.refreshContextNow().catch(() => {}).then(() => { if (this.contextDone === resolve) this.contextDone = null; resolve(); }); }, REFRESH_DELAY);
   });
  }
  async refreshContextNow() {
   var request = this.contextRequest();
   if (!request) { this.contextPreview = null; this.showContext(); return; }
   var asked = JSON.stringify(request);
   if (asked === this.contextAsked && this.contextPreview && Date.now() - this.contextAskedAt < CONTEXT_REUSE_MS) { this.showContext(); return; }
   this.contextPreview = null;
   try { var preview = await this.api('/assistant/context', {method: 'POST', body: asked}); if (JSON.stringify(this.contextRequest()) === asked) { this.contextPreview = preview; this.contextAsked = asked; this.contextAskedAt = Date.now(); } }
   catch (e) { this.contextPreview = null; }
   this.showContext();
  }
  showContext() {
   var chipEl = this.querySelector('[data-assistant-context-chip]'); var shown = !!this.context && !this.contextRemoved;
   chipEl.hidden = !shown; if (!shown) return;
   var preview = this.contextCards ? this.contextPreview : null, state = preview && preview.state;
   var label = this.querySelector('[data-assistant-context-label]'), glyph = this.querySelector('[data-assistant-context-icon]');
   chipEl.classList.remove('wt-mini-chip--bad', 'wt-mini-chip--link');
   if (state === 'BLOCKED') {
    chipEl.classList.add('wt-mini-chip--bad'); glyph.textContent = 'lock'; label.textContent = 'Secret finding';
    chipEl.setAttribute('data-tip', 'Findings of secret rules are never sent to the AI, so nothing about this one is shared: no file, line or rule. Remove to ask about something else.');
   } else if (state === 'UNAVAILABLE') {
    glyph.textContent = 'visibility_off'; label.textContent = 'Page not shared';
    chipEl.setAttribute('data-tip', 'The assistant could not read this page for you. It may have been replaced by a newer scan, you may not have access, or this kind of page is not shared yet. Chat still works; ask about anything.');
   } else if (state === 'OK') {
    chipEl.classList.add('wt-mini-chip--link'); glyph.textContent = 'visibility'; label.textContent = 'Looking at: ' + preview.label;
    chipEl.setAttribute('data-tip', [preview.title].concat(preview.lines || [], ['Built by the server for you. Remove to ask about anything.']).join('\n'));
   } else {
    chipEl.classList.add('wt-mini-chip--link'); glyph.textContent = 'visibility'; label.textContent = 'Looking at: ' + this.context.label;
    chipEl.setAttribute('data-tip', 'The assistant sees which page you are on: ' + this.context.label + '. Remove to ask about anything.');
   }
  }
  /** Read-only unless an admin turned Ruleset actions on; either way nothing changes without approval. */
  modes() { this.querySelector('[data-assistant-actions-chip]').hidden = !this.rulesetActions; this.querySelector('[data-assistant-readonly-chip]').hidden = this.rulesetActions; }
  modelMenu() {
   var menu = this.querySelector('[data-assistant-model-menu]'); menu.replaceChildren();
   var current = (this.models || []).find(m => m.id === this.model.value);
   if (current && !current.efforts.includes(this.effort.value)) this.effort.value = current.efforts[0] || '';
   this.querySelector('[data-assistant-model-label]').textContent = this.model.value + (this.effort.value ? ' · ' + this.effort.value : '');
   text(menu, 'span', 'Model').className = 'wt-menu-label';
   (this.models || []).forEach(m => { var b = text(menu, 'button', m.id); b.type = 'button'; b.className = 'wt-menu-item'; b.setAttribute('aria-pressed', String(m.id === this.model.value)); b.addEventListener('click', () => { if (this.busy) return; this.model.value = m.id; this.modelMenu(); }); });
   if (!current || !current.efforts.length) return;
   text(menu, 'span', 'Effort').className = 'wt-menu-label';
   current.efforts.forEach(e => { var b = text(menu, 'button', e || 'Default'); b.type = 'button'; b.className = 'wt-menu-item'; b.setAttribute('aria-pressed', String(e === this.effort.value)); b.addEventListener('click', () => { if (this.busy) return; this.effort.value = e; this.modelMenu(); menu.closest('details').open = false; }); });
  }
  starters() {
   var start = this.querySelector('[data-assistant-start]'); var empty = this.available && !this.messages.children.length;
   start.hidden = !empty; if (!empty) return;
   var set = STARTERS[this.contextRemoved ? 'any' : pageKind()] || STARTERS.any;
   this.querySelector('[data-assistant-start-title]').textContent = set.title;
   var list = this.querySelector('[data-assistant-starters]'); list.replaceChildren();
   set.items.concat(this.rulesetActions && set.actions ? set.actions : []).forEach(([name, question]) => {
    var b = document.createElement('button'); b.type = 'button'; b.className = 'wt-assistant-starter'; icon(b, name); b.appendChild(document.createTextNode(question));
    b.addEventListener('click', () => { this.input.value = question; this.submit(); }); list.appendChild(b);
   });
  }
  async budget() {
   var el = this.querySelector('[data-assistant-budget]');
   try {
    var b = await this.api('/assistant/budget'); this.querySelector('[data-assistant-budget-label]').textContent = 'Today: ' + dollars(b.usedCostMicros) + ' of ' + dollars(b.dailyCostMicros, true);
    // Where the day went: the person's own spend, the organization's, and each AI feature that has its own share.
    var lines = ['Your day: ' + dollars(b.usedCostMicros) + ' of ' + dollars(b.dailyCostMicros, true)];
    if (b.orgDailyCostMicros) lines.push('Organization: ' + dollars(b.orgUsedCostMicros) + ' of ' + dollars(b.orgDailyCostMicros, true));
    (b.features || []).forEach(f => lines.push(f.name + ' ' + dollars(f.usedCostMicros) + ' of ' + dollars(f.dailyCostMicros, true)));
    lines.push('Resets at midnight UTC.' + ((b.features || []).length ? ' A full share stops only that feature; chat keeps working.' : ''));
    el.setAttribute('data-tip', lines.join('\n')); el.hidden = false;
   }
   catch (e) { el.hidden = true; }
  }
  busyState(value) {
   this.busy = value; this.querySelector('[data-assistant-send]').hidden = value; this.querySelector('[data-assistant-send]').disabled = value;
   this.querySelector('[data-assistant-cancel]').hidden = !value; this.querySelector('.wt-assistant-model summary').toggleAttribute('aria-disabled', value);
  }
  /** User text may carry the page context prefix; it shows as a chip, not as typed text. */
  message(role, value, turnId, result) {
   this.querySelector('[data-assistant-start]').hidden = true;
   var section = text(this.messages, 'section', ''); section.className = 'wt-assistant-message wt-assistant-message--' + (role === 'user' ? 'user' : 'assistant');
   var body = String(value || '');
   if (role === 'user') { var m = CONTEXT_PATTERN.exec(body); if (m) body = body.slice(m[0].length); text(section, 'span', body).className = 'wt-assistant-user-text'; }
   else {
    var who = text(section, 'span', ''); who.className = 'wt-assistant-who'; icon(who, 'auto_awesome').classList.add('wt-ai-icon'); who.appendChild(document.createTextNode('Assistant'));
    if (/^Blocked: secret finding/.test(body)) this.blockedAnswer(section, body);
    else { var answer = document.createElement('div'); markdown(answer, body); section.appendChild(answer); }
    if (result) this.aiChips(section, result);
    if (result) this.cited(section, result.citations);
    if (turnId) this.answerActions(section, turnId, body);
    if (result && Array.isArray(result.changeSets)) result.changeSets.forEach(id => { if (typeof id === 'string') this.changeCard(section, id); });
   }
   this.messages.scrollTop = this.messages.scrollHeight; var scroller = this.querySelector('[data-assistant-body]'); scroller.scrollTop = scroller.scrollHeight;
   return section;
  }
  /** The fixed answer for a secret finding: no model was called, and the way out is the chip above. */
  blockedAnswer(section, body) {
   var box = text(section, 'div', ''); box.className = 'wt-assistant-blocked'; icon(box, 'lock'); text(box, 'span', body);
   text(section, 'span', 'No model was called for this question. Remove the page chip above to ask about something else.').className = 'wt-assistant-note';
  }
  /** Says what kind of help this is: a suggestion about a finding, and any stored AI advice that was read. */
  aiChips(section, result) {
   // Only an assessment that was actually returned is an opinion; turns recorded before this was tracked have no flag and keep the old reading.
   var read = (Array.isArray(result.activity) ? result.activity : []).some(a => a && a.tool === 'get_finding_assessment' && a.status === 'read' && a.opinion !== false);
   var about = result.about || {}, suggest = about.kind === 'finding' && about.state === 'OK';
   if (!suggest && !read) return;
   var row = text(section, 'div', ''); row.className = 'wt-assistant-cited';
   if (suggest) chip(row, 'span', 'lightbulb', 'Suggestion only', 'info', 'You record true or false positive yourself, on the finding. The assistant cannot.');
   if (read) {
    chip(row, 'span', 'psychology', 'AI advice, not a verdict', 'info', 'A stored AI assessment was read. It is advice; a person records the judgment.');
    chip(row, 'span', 'visibility', 'AI opinion seen', 'warn', 'You have now seen an AI opinion on this finding. If you judge it, your judgment is left out of the blind AI-vs-human agreement number. Use Assess on the finding to collect blind data.');
   }
  }
  cited(section, citations) {
   if (!Array.isArray(citations) || !citations.length) return;
   var row = text(section, 'div', ''); row.className = 'wt-assistant-cited'; text(row, 'span', 'Cited');
   citations.forEach(c => { if (!c || !/^\d+$/.test(String(c.id))) return; var a = chip(row, 'a', 'rule', String(c.name || 'Rule ' + c.id), 'link'); a.href = '/rules/' + c.id + '/health'; });
  }
  answerActions(section, turnId, answer) {
   var row = text(section, 'div', ''); row.className = 'wt-assistant-answer-actions';
   var up = iconButton(row, 'thumb_up', 'Helpful'), down = iconButton(row, 'thumb_down', 'Not helpful'), copy = iconButton(row, 'content_copy', 'Copy answer');
   var rate = async (button, rating) => {
    try { await this.api('/assistant/turn/' + encodeURIComponent(turnId) + '/outcome', {method: 'POST', body: JSON.stringify({rating: rating, taskType: null, elapsedSeconds: null, savedSeconds: null})});
     up.setAttribute('aria-pressed', String(button === up)); down.setAttribute('aria-pressed', String(button === down)); this.status.textContent = 'Thanks, feedback saved.'; }
    catch (e) { this.status.textContent = e.message; }
   };
   up.addEventListener('click', () => rate(up, 5)); down.addEventListener('click', () => rate(down, 1));
   copy.addEventListener('click', async () => { try { await navigator.clipboard.writeText(answer); this.status.textContent = 'Answer copied.'; } catch (e) { this.status.textContent = 'Copy is not available in this browser.'; } });
  }
  /** One approval card per prepared change set, read from the server's authoritative preview. */
  async changeCard(section, id) {
   var card = text(section, 'article', ''); card.className = 'wt-change-card'; card.dataset.changeSet = id;
   var base = '/assistant/change-sets/' + encodeURIComponent(id);
   var draw = view => {
    card.replaceChildren(); var p = view.preview || {}; var ops = p.operations || [], sets = p.rulesets || [], repos = p.repositories || [];
    var h = text(card, 'h3', ''); icon(h, 'rule'); h.appendChild(document.createTextNode(changeTitle(ops, sets, repos)));
    var diff = text(card, 'ul', ''); diff.className = 'wt-change-card__diff';
    var added = sets.reduce((n, d) => n + (d.effectiveAdded || []).length, 0), removed = sets.reduce((n, d) => n + (d.effectiveRemoved || []).length, 0);
    var line = (name, tone, label) => { var li = document.createElement('li'); li.style.display = 'contents'; var i = icon(li, name); if (tone) i.classList.add(tone); text(li, 'span', label); diff.appendChild(li); };
    line('add_circle', 'wt-change-plus', added ? '+' + plural(added, 'rule', 'rules') : 'No rules added');
    line('remove_circle_outline', 'wt-change-minus', removed ? '−' + plural(removed, 'rule', 'rules') : 'No rules removed');
    sets.forEach(d => inheritance(d).forEach(change => line('account_tree', null, change)));
    if (repos.length) line('code', null, 'Affects ' + plural(repos.length, 'repository', 'repositories') + ': ' + repos.map(a => a.before && a.before.name).filter(Boolean).slice(0, 5).join(', '));
    var chips = text(card, 'div', ''); chips.className = 'wt-chip-row';
    sets.forEach(d => { if (d.blockingReduced) chip(chips, 'span', 'gpp_maybe', 'Blocking reduced', 'bad', 'Pull requests will be blocked for fewer findings after this change.'); if ((d.secretsCoverageRemoved || []).length) chip(chips, 'span', 'key_off', 'Secrets coverage removed', 'bad', 'Secrets rules leave this ruleset: ' + d.secretsCoverageRemoved.join(', ')); });
    var draft = view.status === 'DRAFT', expired = draft && Date.now() >= view.expiresAt;
    if (draft) {
     chip(chips, 'span', 'fact_check', 'Preview checked', 'ok', 'The server worked out exactly what changes, from the saved rulesets right now.');
     chip(chips, 'span', 'timer', expired ? 'Preview expired' : 'Expires in ' + Math.max(1, Math.ceil((view.expiresAt - Date.now()) / MINUTE)) + ' min', expired ? 'warn' : null, 'If anyone changes rulesets first, or 30 minutes pass, the preview is checked again.');
     chip(chips, 'span', 'how_to_reg', 'Needs your approval', 'warn', 'Nothing changes until you press Approve and apply.');
    }
    var full = chip(chips, 'a', 'open_in_new', 'Full preview', 'link', 'Every field before and after.'); full.href = base + '/review';
    var status = text(card, 'p', ''); status.className = 'wt-assistant-status wt-muted'; status.setAttribute('role', 'status');
    if (draft) {
     var actions = text(card, 'div', ''); actions.className = 'wt-change-card__actions';
     var act = async (path, body) => { go.disabled = discard.disabled = true; try { draw(await this.api(base + path, {method: 'POST', body: JSON.stringify(body)})); } catch (e) { status.textContent = e.message; go.disabled = discard.disabled = false; } };
     var discard = document.createElement('md-outlined-button'); discard.textContent = 'Discard'; actions.appendChild(discard);
     var go = document.createElement('md-filled-button'); go.setAttribute('has-icon', '');
     var deletes = ops.some(o => o.type === 'DELETE');
     if (deletes) { go.textContent = 'Review and delete'; go.setAttribute('href', base + '/review'); }
     else if (expired) { go.textContent = 'Check again'; go.addEventListener('click', () => act('/refresh', {})); }
     else { var gi = icon(go, 'check'); gi.slot = 'icon'; go.appendChild(document.createTextNode('Approve and apply')); go.addEventListener('click', () => act('/apply', {version: view.version, contentHash: view.contentHash, deletionNames: {}})); }
     actions.appendChild(go); discard.addEventListener('click', () => act('/cancel', {}));
    } else if (view.status === 'APPLIED') {
     var receipt = text(card, 'div', ''); receipt.className = 'wt-change-card__receipt'; icon(receipt, 'check_circle');
     text(receipt, 'span', 'Applied ' + (view.receipt && view.receipt.appliedAt ? when(view.receipt.appliedAt) : '') + ' · receipt #' + id.slice(0, 4));
     var link = chip(receipt, 'a', 'receipt_long', 'Receipt', 'link', 'Who approved, what changed and the exact before/after. Kept after the chat expires.'); link.href = base + '/review';
    } else chip(chips, 'span', 'block', 'Discarded', null, 'Nothing was changed.');
   };
   try { draw(await this.api(base)); } catch (e) { card.replaceChildren(); text(card, 'p', 'This change set is unavailable: ' + e.message).className = 'wt-muted'; }
  }
  async submit() {
   if (!this.available || this.busy || !this.input.value.trim()) return;
   var value = this.input.value;
   var payload = {sessionId: this.session, message: this.withContext(value), model: this.model.value, effort: this.effort.value};
   var request = this.contextRequest(); if (request) payload.context = request;
   var draft = this.draftText(); if (draft) payload.draft = draft;
   var signature = JSON.stringify(payload);
   if (!this.pendingSubmit || this.pendingSubmit.signature !== signature) this.pendingSubmit = {signature: signature, payload: Object.assign({idempotencyKey: crypto.randomUUID()}, payload)};
   this.busyState(true); this.status.textContent = 'Sending…';
   try {
    var result = await this.api('/assistant/turn', {method: 'POST', body: JSON.stringify(this.pendingSubmit.payload)});
    this.pendingSubmit = null; this.session = result.sessionId; this.turn = result.turnId; this.shownTurn = null; this.contextState = result.context || 'NONE';
    this.turnAbout = {kind: request && request.kind, state: this.contextState};
    var sent = this.message('user', value); this.input.value = ''; this.watch();
    if (payload.draft) { var attached = text(sent, 'div', ''); attached.className = 'wt-assistant-cited'; chip(attached, 'span', 'edit_note', 'Draft attached · ' + plural(payload.draft.split('\n').length, 'line', 'lines'), 'info'); this.clearDraft(); }
   } catch (e) {
    // A draft the server refused will be refused again, so it is dropped instead of retried.
    if (payload.draft && e.status === 400) { this.pendingSubmit = null; this.draftRefused(e.message); this.clearDraft(); this.status.textContent = ''; }
    else this.status.textContent = e.message + ' Retry sends the same request.';
    this.busyState(false);
   }
  }
  /** The page the person is on (name and, from page buttons, ids) prefixes the message; never page data. */
  /** With page context cards on, the server rebuilds the page from ids and the message carries no page text. */
  contextRequest() {
   if (!this.contextCards || !this.context || this.contextRemoved) return null;
   var r = this.context.request; return r ? {v: r.v, kind: r.kind, ids: r.ids} : null;
  }
  withContext(value) {
   // The page name stays in the message when ids cannot carry the page, or when the page's own instruction needs to travel with it.
   if (!this.context || this.contextRemoved || (this.contextRequest() && !this.context.detail)) return value;
   var label = clip(this.context.label + (this.context.detail ? ' · ' + this.context.detail : '') + ' · ' + location.pathname);
   return '[Looking at: ' + label + ']\n\n' + value;
  }
  // Durable progress arrives over SSE; a refused or closed stream falls back to polling.
  watch() {
   this.stopStream(); clearTimeout(this.timer); if (typeof EventSource !== 'function') { this.poll(); return; }
   var stream = new EventSource('/assistant/turn/' + encodeURIComponent(this.turn) + '/events'); this.stream = stream;
   stream.addEventListener('turn', e => { if (this.stream !== stream) return; var result; try { result = JSON.parse(e.data); } catch (err) { return; } if (this.render(result)) this.stopStream(); });
   stream.addEventListener('end', () => { if (this.stream !== stream) return; this.stopStream(); this.poll(); });
   stream.onerror = () => { if (this.stream === stream && stream.readyState === EventSource.CLOSED) { this.stream = null; this.poll(); } };
  }
  stopStream() { if (this.stream) { this.stream.close(); this.stream = null; } }
  render(result) {
   var activity = (Array.isArray(result.activity) ? result.activity : []).filter(a => a && typeof a.tool === 'string').map(a => a.tool.replace(/_/g, ' ') + ' (' + a.status + ')');
   this.status.textContent = result.status === 'COMPLETED' ? '' : (result.status === 'FAILED' ? 'The answer failed' : result.status === 'CANCELED' ? 'Stopped' : 'Working') + (result.error ? ' — ' + result.error : '') + (activity.length ? ' · ' + activity.join(', ') : '');
   if (result.status === 'COMPLETED' && activity.length) this.status.textContent = 'Read: ' + activity.join(', ');
   if (result.expiresAt) this.expiry(result.expiresAt);
   if (result.status === 'COMPLETED') { if (this.shownTurn !== this.turn) { this.message('assistant', result.answer, this.turn, Object.assign({}, result, {about: this.turnAbout})); this.shownTurn = this.turn; } this.busyState(false); this.budget(); return true; }
   if (['FAILED', 'CANCELED'].includes(result.status)) { this.busyState(false); this.budget(); return true; }
   return false;
  }
  expiry(at) { var el = this.querySelector('[data-assistant-expiry]'); el.textContent = 'Kept until ' + shortWhen(at); el.title = when(at); el.hidden = false; }
  async poll() {
   clearTimeout(this.timer);
   try { var result = await this.api('/assistant/turn/' + encodeURIComponent(this.turn)); if (!this.render(result)) this.timer = setTimeout(() => this.poll(), 2000); }
   catch (e) { this.status.textContent = e.message; if (e.status === 403 || e.status === 404 || e.status === 410) this.busyState(false); else { this.status.textContent += ' Reconnecting…'; this.timer = setTimeout(() => this.poll(), 2000); } }
  }
  async cancel() { try { await this.api('/assistant/turn/' + encodeURIComponent(this.turn) + '/cancel', {method: 'POST'}); clearTimeout(this.timer); this.stopStream(); this.status.textContent = 'Stopped'; this.busyState(false); } catch (e) { this.status.textContent = e.message; } }
  async history() {
   try {
    var list = await this.api('/assistant/history?offset=' + this.historyOffset); var area = this.querySelector('[data-assistant-history-list]'); area.replaceChildren(); area.hidden = false;
    var head = text(area, 'span', 'Earlier chats' + (this.retentionDays ? ' (kept ' + plural(this.retentionDays, 'day', 'days') + ')' : '')); head.className = 'wt-eyebrow';
    if (!list.length) text(area, 'p', 'No earlier chats.').className = 'wt-muted';
    list.forEach(s => this.historyRow(area, s));
    var pager = text(area, 'div', ''); pager.className = 'wt-chip-row';
    if (this.historyOffset > 0) { var prev = text(pager, 'button', 'Newer'); prev.type = 'button'; prev.className = 'wt-menu-item'; prev.addEventListener('click', () => { this.historyOffset -= 20; this.history(); }); }
    if (list.length === 20) { var next = text(pager, 'button', 'Older'); next.type = 'button'; next.className = 'wt-menu-item'; next.addEventListener('click', () => { this.historyOffset += 20; this.history(); }); }
   } catch (e) { this.status.textContent = e.message; }
  }
  /** One earlier chat: its title (or date and model for old chats), and a trash button that asks before deleting. */
  historyRow(area, s) {
   var row = document.createElement('div'); row.className = 'wt-assistant-history-row'; area.appendChild(row);
   var open = text(row, 'button', s.title || (shortWhen(s.started_at) + ' · ' + s.model)); open.type = 'button'; open.className = 'wt-menu-item';
   open.title = s.title ? when(s.started_at) + ' · ' + s.model : when(s.started_at);
   open.addEventListener('click', () => this.reopen(s.session_id));
   iconButton(row, 'delete_outline', 'Delete this chat').addEventListener('click', () => this.confirmDelete(row, s));
  }
  confirmDelete(row, s) {
   row.replaceChildren(); text(row, 'span', 'Delete this chat?').className = 'wt-muted';
   var yes = text(row, 'button', 'Delete'); yes.type = 'button'; yes.className = 'wt-menu-item wt-assistant-history-confirm';
   var no = text(row, 'button', 'Keep'); no.type = 'button'; no.className = 'wt-menu-item';
   yes.addEventListener('click', () => this.removeChat(s.session_id));
   no.addEventListener('click', () => this.history()); no.focus();
  }
  async removeChat(id) {
   try {
    await this.api('/assistant/history/' + encodeURIComponent(id), {method: 'DELETE'});
    if (this.session === id) this.newChat();
    this.status.textContent = 'Chat deleted.'; await this.history();
   } catch (e) { this.status.textContent = e.message; await this.history(); }
  }
  async reopen(id) {
   if (this.busy) { this.status.textContent = 'Stop or finish the current answer first.'; return; }
   this.status.textContent = 'Loading chat…';
   try {
    var data = await this.api('/assistant/history/' + encodeURIComponent(id));
    this.stopStream(); clearTimeout(this.timer); this.session = id; this.pendingSubmit = null; this.messages.replaceChildren(); this.status.textContent = '';
    var lastAssistant = null; data.messages.forEach(m => { var s = this.message(m.role, m.text); if (m.role !== 'user') lastAssistant = s; });
    this.model.value = data.session.model; this.effort.value = data.session.effort; this.modelMenu(); this.expiry(data.session.expires_at);
    this.querySelector('[data-assistant-history-list]').hidden = true;
    var active = data.turns.find(t => ['QUEUED', 'RUNNING', 'RECOVERING'].includes(t.status));
    if (active) { this.turn = active.turn_id; this.busyState(true); this.watch(); }
    else {
     var last = data.turns.length ? data.turns[data.turns.length - 1] : null; this.turn = last ? last.turn_id : null; this.shownTurn = this.turn;
     if (last && last.status === 'COMPLETED' && lastAssistant) this.answerActions(lastAssistant, last.turn_id, lastAssistant.textContent);
    }
    this.starters();
   } catch (e) { this.status.textContent = e.message; }
  }
 }
 /** Plain-words title for a change set: what happens to which ruleset. */
 function changeTitle(ops, sets, repos) {
  var name = d => (d.after || d.before || {}).name || 'a ruleset';
  var first = ops[0] || {}; var d = sets[0];
  var more = ops.length > 1 ? ' (+' + plural(ops.length - 1, 'more change', 'more changes') + ')' : '';
  switch (first.type) {
   case 'CREATE': return 'Create ruleset "' + (first.name || (d ? name(d) : 'new')) + '"' + more;
   case 'DELETE': return 'Delete ' + (d ? '"' + name(d) + '"' : 'a ruleset') + more;
   case 'DEFAULT': return 'Make ' + (d ? '"' + name(d) + '"' : 'a ruleset') + ' the default' + more;
   case 'ASSIGN': return 'Change the ruleset of ' + plural(repos.length, 'repository', 'repositories') + more;
   case 'INHERIT': return 'Change what ' + (d ? '"' + name(d) + '"' : 'a ruleset') + ' includes' + more;
   case 'MEMBERSHIP': return 'Change the rules in ' + (d ? '"' + name(d) + '"' : 'a ruleset') + more;
   default: return 'Edit ' + (d ? '"' + name(d) + '"' : 'a ruleset') + more;
  }
 }
 function inheritance(d) {
  var before = (d.before && d.before.inherited) || [], after = (d.after && d.after.inherited) || [];
  return after.filter(x => !before.includes(x)).map(x => 'Includes ' + x).concat(before.filter(x => !after.includes(x)).map(x => 'No longer includes ' + x));
 }
 if (!customElements.get('wt-assistant-drawer')) customElements.define('wt-assistant-drawer', AssistantDrawer);
 document.addEventListener('click', function (e) {
  var target = e.target.closest('[data-assistant-open],[data-assistant-explain]'); if (!target) return;
  var drawer = document.querySelector('wt-assistant-drawer'); if (!drawer) return;
  // The round launcher opens on the current page; page buttons also share their own context.
  if (!target.dataset.assistantContext && !target.dataset.assistantExplain && !target.dataset.assistantSubject) { drawer.open(null, null, target); return; }
  drawer.open(target.dataset.assistantExplain ? 'Explain rule id ' + target.dataset.assistantExplain + ' using its definition, engine playbook, limitations and health evidence.' : null, target);
 });
 window.wtAssistantMarkdown = markdown;
})();

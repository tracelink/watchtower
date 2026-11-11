(function () {
 'use strict';
 // Weekly Home digest (board approved 2026-10-24): one chip beside the system status that opens a small popover with
 // a few short lines about this week's counts. The chip appears only when the feature is on and there is a digest to
 // read or the person may write one. All text is set with textContent.
 var anchor = document.querySelector('[data-home-digest]');
 if (!anchor || anchor.dataset.ready) return;
 anchor.dataset.ready = 'true';
 var button = anchor.querySelector('button'), label = anchor.querySelector('[data-digest-label]');
 var info = null, popover = null, busy = false, message = null;
 var TRENDS = {steady: ['drag_handle', 'steady'], up: ['trending_up', 'up'], down: ['trending_down', 'down'], attention: ['priority_high', 'attention']};

 function el(parent, tag, value, className) { var node = document.createElement(tag); if (value) node.textContent = value; if (className) node.className = className; parent.appendChild(node); return node; }
 function icon(parent, name) { var node = el(parent, 'span', name, 'material-icons'); node.setAttribute('aria-hidden', 'true'); return node; }
 function chip(parent, iconName, value, tone, tip) {
  var node = el(parent, 'span', '', 'wt-mini-chip' + (tone ? ' wt-mini-chip--' + tone : ''));
  if (iconName) icon(node, iconName);
  node.appendChild(document.createTextNode(value));
  if (tip) { node.setAttribute('data-tip', tip); node.tabIndex = 0; }
  return node;
 }
 async function call(method) {
  var headers = {Accept: 'application/json'};
  if (method === 'POST') headers[anchor.dataset.csrfHeader] = anchor.dataset.csrfToken;
  var response = await fetch('/home/digest', {method: method, headers: headers});
  var body = {};
  try { body = await response.json(); } catch (e) { body = {}; }
  if (!response.ok) { var error = new Error(body.error || 'The digest is unavailable right now (' + response.status + ').'); error.status = response.status; throw error; }
  return body;
 }
 function day(ms) { return new Date(ms).toLocaleDateString('en-US', {month: 'short', day: 'numeric', timeZone: 'UTC'}); }
 function range(digest) {
  var start = new Date(digest.windowStart), end = new Date(digest.windowEnd - 1);
  var sameMonth = start.getUTCMonth() === end.getUTCMonth();
  return day(digest.windowStart) + ' – ' + (sameMonth ? end.getUTCDate() : day(digest.windowEnd - 1));
 }
 function note(parent, iconName, tone, text) {
  var box = el(parent, 'div', '', 'wt-ai-note wt-ai-note--' + tone); icon(box, iconName); el(box, 'span', text); return box;
 }
 function number(value) { return Number(value || 0).toLocaleString('en-US'); }

 function renderDigest(parent, digest) {
  var points = digest.points || [];
  if (digest.status === 'OK' && points.length) {
   points.forEach(function (p) {
    var look = TRENDS[p.trend] || TRENDS.steady, line = el(parent, 'div', '', 'wt-ai-trend-line');
    var tile = el(line, 'span', '', 'wt-ai-trend wt-ai-trend--' + look[1]); icon(tile, look[0]);
    el(line, 'span', p.text);
   });
   var meta = el(parent, 'div', '', 'wt-meta-chips');
   chip(meta, 'auto_awesome', 'AI summary of counts', 'ai', 'Written by the assistant from counts only. It is not a judgment.');
   chip(meta, 'schedule', 'Made ' + new Date(digest.createdAt).toLocaleString(undefined, {weekday: 'short', hour: '2-digit', minute: '2-digit'}), '', 'When this digest was written.');
   chip(meta, 'visibility_off', 'No findings or names', '', 'Only aggregate counts were sent: no finding, file, repository or person.');
   return;
  }
  // No usable lines: the counts on their own, from the digest's stored numbers.
  var week = ((digest.counts || {}).this_week) || {}, now = ((digest.counts || {}).now) || {}, row = el(parent, 'div', '', 'wt-meta-chips');
  chip(row, 'task_alt', number(week.scans_finished) + ' scans', '', 'Scans finished in the last 7 days.');
  chip(row, 'error_outline', number(week.scans_failed_or_incomplete) + ' failed', week.scans_failed_or_incomplete > 0 ? 'bad' : '', 'Scans that failed or did not finish.');
  chip(row, 'bug_report', number(week.findings) + ' findings', '', 'Findings recorded in the last 7 days.');
  chip(row, 'link_off', number(now.integrations_failing) + ' integrations failing', now.integrations_failing > 0 ? 'bad' : '', 'Integrations whose last health check failed.');
  note(parent, 'info', 'info', 'The assistant could not write a summary this time, so these are the counts only.');
 }

 function render() {
  if (!popover) return;
  popover.replaceChildren();
  var head = el(popover, 'div', '', 'wt-ai-diagnosis__head');
  icon(head, 'auto_awesome').classList.add('wt-ai-icon');
  el(head, 'strong', 'Last 7 days');
  if (info.digest) chip(head, 'date_range', range(info.digest), '', 'The 7 full days this digest covers.');
  if (info.canWrite && info.digest) {
   var refresh = el(head, 'button', '', 'wt-icon-action'); refresh.type = 'button'; refresh.setAttribute('aria-label', 'Write a new digest');
   refresh.setAttribute('data-tip', "Write a new digest from today's counts. Once every 5 minutes."); refresh.setAttribute('data-digest-refresh', ''); icon(refresh, 'refresh');
   refresh.addEventListener('click', write);
  }
  if (info.digest) renderDigest(popover, info.digest);
  else {
   note(popover, 'schedule', 'info', 'No digest yet. One is written once a week. You can write the first one now.');
   var first = el(popover, 'button', '', 'btn btn-primary btn-sm'); first.type = 'button'; first.setAttribute('data-digest-write', '');
   icon(first, 'auto_awesome'); first.appendChild(document.createTextNode('Write digest')); first.addEventListener('click', write);
  }
  if (message) note(popover, message.icon, message.tone, message.text);
 }
 async function write() {
  if (busy) return;
  busy = true; message = {icon: 'hourglass_top', tone: 'info', text: 'Writing a digest…'}; render();
  try {
   var result = await call('POST');
   if (result.state === 'OK') { info.digest = result.digest; message = null; }
   else message = {icon: 'info', tone: 'warn', text: result.message || 'A digest could not be written.'};
  } catch (e) { message = {icon: e.status === 429 ? 'hourglass_empty' : 'info', tone: 'warn', text: e.message}; }
  busy = false; render();
 }
 function close() { if (popover) { popover.remove(); popover = null; } button.setAttribute('aria-expanded', 'false'); }
 function open() {
  popover = el(anchor, 'div', '', 'wt-ai-diagnosis wt-ai-popover'); popover.setAttribute('role', 'dialog'); popover.setAttribute('aria-label', 'Weekly digest');
  button.setAttribute('aria-expanded', 'true'); message = null; render();
 }
 button.addEventListener('click', function (event) { event.stopPropagation(); if (popover) close(); else open(); });
 // A click on something the popover just re-drew (the refresh button) is detached by now, but it was inside.
 document.addEventListener('click', function (event) { if (popover && event.target.isConnected && !anchor.contains(event.target)) close(); });
 document.addEventListener('keydown', function (event) { if (event.key === 'Escape' && popover) { close(); button.focus(); } });

 call('GET').then(function (result) {
  info = result;
  // Nothing to show: the feature is off, or there is no digest yet and this person cannot write one.
  if (!info.enabled || (!info.digest && !info.canWrite)) { anchor.remove(); return; }
  label.textContent = info.digest ? 'Weekly digest' : 'Digest';
  anchor.hidden = false;
 }).catch(function () { anchor.remove(); });
}());

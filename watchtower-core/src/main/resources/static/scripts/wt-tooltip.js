(() => {
 'use strict';
 // One shared hover/focus tooltip for any element with data-tip (UAT walkthrough, 2026-10-15).
 // A single fixed-position bubble on <body>, so scrolling tables never clip it. The same text is
 // each element's accessible name, so the bubble is a visual aid only (aria-hidden).
 if (window.watchtowerTooltipInstalled) return;
 window.watchtowerTooltipInstalled = true;
 const MARGIN = 8;
 let bubble = null;
 let current = null;
 // A manual popover sits in the top layer, so tips also show over an open modal dialog (the
 // dialog itself is in the top layer, above any z-index on <body>).
 const popoverOpen = tip => {
  try { return tip.matches(':popover-open'); } catch (e) { return false; }
 };
 const bubbleElement = () => {
  if (!bubble) {
   bubble = document.createElement('div');
   bubble.className = 'wt-tip-bubble';
   bubble.setAttribute('aria-hidden', 'true');
   if (typeof bubble.showPopover === 'function') bubble.setAttribute('popover', 'manual');
   bubble.hidden = true;
   document.body.appendChild(bubble);
  }
  return bubble;
 };
 const hide = () => {
  if (bubble) {
   if (popoverOpen(bubble)) bubble.hidePopover();
   bubble.hidden = true;
  }
  current = null;
 };
 const show = target => {
  const text = target.getAttribute('data-tip');
  if (!text) return;
  const tip = bubbleElement();
  tip.textContent = text;
  tip.hidden = false;
  if (tip.hasAttribute('popover')) {
   // Re-open so it stacks above a dialog opened since it was last shown.
   if (popoverOpen(tip)) tip.hidePopover();
   try { tip.showPopover(); } catch (e) { /* not connected yet: shown as a plain fixed element */ }
  }
  current = target;
  const anchor = target.getBoundingClientRect();
  const left = Math.max(MARGIN, Math.min(anchor.left + anchor.width / 2 - tip.offsetWidth / 2,
   window.innerWidth - tip.offsetWidth - MARGIN));
  const above = anchor.top - tip.offsetHeight - MARGIN;
  tip.style.left = left + 'px';
  tip.style.top = (above >= MARGIN ? above : anchor.bottom + MARGIN) + 'px';
 };
 const tipFor = node => (node instanceof Element ? node.closest('[data-tip]') : null);
 document.addEventListener('pointerover', event => {
  const target = tipFor(event.target);
  if (target && target !== current) show(target);
  else if (!target && current) hide();
 });
 document.addEventListener('pointerleave', hide);
 document.addEventListener('focusin', event => { const target = tipFor(event.target); if (target) show(target); });
 document.addEventListener('focusout', hide);
 document.addEventListener('keydown', event => { if (event.key === 'Escape') hide(); });
 window.addEventListener('scroll', hide, true);
 document.addEventListener('htmx:beforeSwap', hide);
})();

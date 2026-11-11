// IMPROVEMENT_PLAN.md Phase 11 Section E: a small material-style ripple on every .btn, delegated
// from document so it works on buttons rendered after this script runs (htmx-boosted swaps,
// Alpine-rendered rows) without re-binding anything. Guarded by prefers-reduced-motion at the
// top of the handler rather than in CSS alone, so a reduced-motion user never gets a ripple span
// inserted into the DOM at all, not just one that's visually suppressed.
document.addEventListener('click', (event) => {
	if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
		return;
	}
	const button = event.target.closest('.btn');
	if (!button) {
		return;
	}

	const rect = button.getBoundingClientRect();
	// Diameter large enough that the ripple's growth (2.5x, see the keyframe in components.css)
	// covers the button's farthest corner from the click point, whichever corner that is.
	const radius = Math.max(
			Math.hypot(event.clientX - rect.left, event.clientY - rect.top),
			Math.hypot(event.clientX - rect.right, event.clientY - rect.top),
			Math.hypot(event.clientX - rect.left, event.clientY - rect.bottom),
			Math.hypot(event.clientX - rect.right, event.clientY - rect.bottom));
	const diameter = radius * 2;

	const ripple = document.createElement('span');
	ripple.className = 'wt-btn-ripple';
	ripple.style.width = ripple.style.height = `${diameter}px`;
	ripple.style.left = `${event.clientX - rect.left - radius}px`;
	ripple.style.top = `${event.clientY - rect.top - radius}px`;
	button.appendChild(ripple);
	ripple.addEventListener('animationend', () => ripple.remove());
});

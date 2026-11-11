(function () {
	'use strict';

	var MIN = 30;
	var MAX = 70;
	var STEP = 2;
	var media = window.matchMedia('(max-width: 991.98px)');

	function clamp(value) {
		return Math.min(MAX, Math.max(MIN, value));
	}

	function initialize(workspace) {
		if (workspace.dataset.splitInitialized === 'true') {
			return;
		}
		workspace.dataset.splitInitialized = 'true';
		var handle = workspace.querySelector('[data-workspace-resizer]');
		if (!handle) {
			return;
		}
		var defaultRatio = clamp(Number(workspace.dataset.splitDefault) || 45);
		var storageKey = 'watchtower-split-' + (workspace.dataset.splitKey || 'workspace');
		var ratio = defaultRatio;
		try {
			var saved = Number(localStorage.getItem(storageKey));
			if (saved >= MIN && saved <= MAX) {
				ratio = saved;
			}
		} catch (error) {
			// Storage can be unavailable in private browsing; resizing still works for this page.
		}

		function apply(next, persist) {
			ratio = clamp(Math.round(next));
			workspace.style.setProperty('--wt-split-percent', ratio + '%');
			handle.setAttribute('aria-valuenow', String(ratio));
			if (persist) {
				try {
					localStorage.setItem(storageKey, String(ratio));
				} catch (error) {
					// Keep the in-memory ratio when storage is blocked.
				}
			}
		}

		function syncMobile() {
			var disabled = media.matches;
			handle.tabIndex = disabled ? -1 : 0;
			handle.setAttribute('aria-disabled', String(disabled));
		}

		handle.addEventListener('keydown', function (event) {
			if (media.matches) {
				return;
			}
			var next = ratio;
			if (event.key === 'ArrowLeft') next -= STEP;
			else if (event.key === 'ArrowRight') next += STEP;
			else if (event.key === 'Home') next = MIN;
			else if (event.key === 'End') next = MAX;
			else return;
			event.preventDefault();
			apply(next, true);
		});

		handle.addEventListener('dblclick', function () {
			if (!media.matches) {
				apply(defaultRatio, true);
			}
		});

		handle.addEventListener('pointerdown', function (event) {
			if (media.matches || event.button !== 0) {
				return;
			}
			event.preventDefault();
			handle.classList.add('is-dragging');
			if (handle.setPointerCapture) handle.setPointerCapture(event.pointerId);
			function move(moveEvent) {
				var bounds = workspace.getBoundingClientRect();
				if (bounds.width > 0) {
					apply(((moveEvent.clientX - bounds.left) / bounds.width) * 100, false);
				}
			}
			function end() {
				handle.classList.remove('is-dragging');
				apply(ratio, true);
				document.removeEventListener('pointermove', move);
				document.removeEventListener('pointerup', end);
				document.removeEventListener('pointercancel', end);
			}
			document.addEventListener('pointermove', move);
			document.addEventListener('pointerup', end);
			document.addEventListener('pointercancel', end);
		});

		apply(ratio, false);
		syncMobile();
		if (media.addEventListener) media.addEventListener('change', syncMobile);
	}

	document.querySelectorAll('[data-split-workspace]').forEach(initialize);
})();

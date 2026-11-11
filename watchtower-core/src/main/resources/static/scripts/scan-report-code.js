// Synchronizes the selected finding with its source line and jumps to that line when requested.
//
// The link is a plain in-page anchor to #wt-code-section, so with scripting off it still lands on
// the code - this only makes it land on the right line, expanding that file's <details> panel
// first if it is collapsed. Selecting a finding highlights its line without stealing scroll.
//
// Loaded per-page via PullRequestReportController.addScriptReference, which places it inside
// #content, so it re-runs on every htmx-boosted navigation. It binds to the section/table
// elements rather than document, and both are replaced wholesale on each swap, so no listener
// accumulates across navigations.
(function () {
	var section = document.getElementById('wt-code-section');
	var workspace = document.querySelector('[data-finding-workspace]');
	if (!section || !workspace) {
		return;
	}

	var TARGET_CLASS = 'wt-code-line-target';

	// These values are file paths from the scanner, not identifiers, and they go inside a quoted
	// attribute selector - so the escaping that matters is for quotes and backslashes, not the
	// identifier escaping CSS.escape() performs.
	function escapeAttributeValue(value) {
		return String(value).replace(/(["\\])/g, '\\$1');
	}

	function prefersReducedMotion() {
		return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
	}

	function showSource(file, line, shouldScroll) {
		if (!file) {
			return false;
		}

		var panel = section.querySelector(
			'details[data-file="' + escapeAttributeValue(file) + '"]');
		if (!panel) {
			return false;
		}

		panel.open = true;
		var target = panel.querySelector(
			'.wt-code-line[data-line="' + escapeAttributeValue(line) + '"]') || panel;

		Array.prototype.forEach.call(section.querySelectorAll('.' + TARGET_CLASS), function (el) {
			el.classList.remove(TARGET_CLASS);
		});
		target.classList.add(TARGET_CLASS);
		if (shouldScroll) {
			target.scrollIntoView({
				block: 'center',
				behavior: prefersReducedMotion() ? 'auto' : 'smooth'
			});
		}
		return true;
	}

	workspace.addEventListener('click', function (event) {
		var link = event.target.closest('a.wt-loc');
		if (!link) {
			return;
		}
		var file = link.getAttribute('data-file');
		var line = link.getAttribute('data-line');
		if (!file) {
			return;
		}

		if (!showSource(file, line, true)) {
			// No code panel for this file. Leave the anchor alone so the browser still scrolls to
			// the code section rather than doing nothing at all.
			return;
		}

		event.preventDefault();
	});

	workspace.addEventListener('wt:finding-selected', function (event) {
		showSource(event.detail.file, event.detail.line, event.detail.scroll);
	});
})();

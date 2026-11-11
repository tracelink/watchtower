// Global fetch/navigation feedback: the whole app is body-boosted (hx-boost="true" on
// <body>, see fragments/container.html), so every internal navigation - pagination, the
// Report link, sidebar links - goes through htmx. These two events bracket exactly one
// htmx-initiated request each (boosted nav, hx-get, form submit alike), so a single
// listener pair here covers all of it instead of adding hx-indicator to every template.
// Bound to `document`, not `document.body`. This script is loaded from <head>, and at that
// point the parser has not reached <body> yet, so document.body is null - the previous version
// threw "Cannot read properties of null (reading 'addEventListener')" on every page load and
// the loading bar never armed once. htmx events bubble all the way up, so document is both a
// valid target at parse time and still correct after a boosted swap. document.body inside the
// handlers is safe: by the time a request fires, the document has long since parsed.
document.addEventListener('htmx:beforeRequest', function () {
	document.body.classList.add('wt-loading');
});
document.addEventListener('htmx:afterRequest', function () {
	document.body.classList.remove('wt-loading');
});

// Spring Security redirects an expired-session request to /login. htmx follows that redirect,
// but the application shell asks it to select #content from every response. The standalone login
// page has no #content element, so htmx updates the browser URL while leaving the expired page on
// screen. Detect the final response URL before swapping and use a full navigation for the login
// page. The same-origin check prevents an unexpected redirect from becoming client-side
// navigation, and replace() keeps the stale authenticated shell out of browser history.
document.addEventListener('htmx:beforeSwap', function (event) {
	var xhr = event.detail && event.detail.xhr;
	if (!xhr || !xhr.responseURL) {
		return;
	}

	var responseUrl;
	try {
		responseUrl = new URL(xhr.responseURL, window.location.href);
	} catch (error) {
		return;
	}

	if (responseUrl.origin === window.location.origin
			&& responseUrl.pathname.endsWith('/login')) {
		event.detail.shouldSwap = false;
		window.location.replace(responseUrl.href);
	}
});

// IMPROVEMENT_PLAN_MATERIAL_UI.md Section F: the original IMPROVEMENT_PLAN.md item 11.0 handler
// here dismissed a Bootstrap .modal.show/.modal-backdrop left open before a boosted swap - dead
// since Section E's last wave (Wave 8) converted the app's final Bootstrap modal to md-dialog.
// Confirmed dead, not just superseded: zero `.modal` (as a live wrapper class, not `.modal-body`/
// `.modal-dialog` etc.) or `data-bs-toggle="modal"` markup remains anywhere in the repo. md-dialog
// uses the native <dialog>/top-layer rather than Bootstrap's body-appended backdrop, so close any
// dialog left open before a boosted swap - an md-dialog can live inside #content (per-page, like
// the pilot's #saveRegexRuleDialog) and would otherwise be mid-open when its content is replaced
// out from under it.
document.addEventListener('htmx:beforeSwap', function () {
	document.querySelectorAll('md-dialog[open]').forEach(function (dialog) {
		dialog.close();
	});
});

// Material Web migration: md-outlined-select's initial pre-selection sync is a genuine race, not
// a scripted-test artifact. Its firstUpdated() awaits its internal <md-menu> sub-component's own
// async update chain before reading which md-select-option carries the [selected] attribute -
// that chain does not reliably finish before a user can act on the page. Confirmed live
// (regex/rule-edit and eslint/rule-edit, both already-shipped waves): reloading the page and
// reading the Priority select's .value returned "" in roughly 2 of 5 trials, even after a 5s
// wait, while the correct option stayed marked selected="" in the DOM the whole time - and the
// same race reproduces through a real fill()-into-a-different-field + real button click, not
// just a raw script read, producing a spurious "<Field> cannot be null" rejection on an edit that
// never touched the select. select.reset() is md-select's own public API for "recompute value
// and display text from each option's current selected attribute" (used internally for native
// <form> reset) - calling it here reuses that instead of reimplementing the sync. Bound the same
// way other shell helpers are: DOMContentLoaded for the first real page load (this script lives
// in <head>, outside the htmx-boosted #content region) and htmx:afterSettle for
// every subsequent boosted swap.
function wtResyncOutlinedSelects() {
	document.querySelectorAll('md-outlined-select').forEach(function (select) {
		if (typeof select.reset === 'function') {
			select.reset();
		}
	});
}

if (document.readyState === 'loading') {
	document.addEventListener('DOMContentLoaded', wtResyncOutlinedSelects, { once: true });
} else {
	wtResyncOutlinedSelects();
}
document.addEventListener('htmx:afterSettle', wtResyncOutlinedSelects);

// A boosted response swaps only #content, so its <head>/<title> never reaches the document.
// Keep the browser title synchronized across swaps, pagination, history restoration, and the
// initial full page load.
function wtSyncShellHeading(event) {
	var heading = document.querySelector('#content h1.page-title');
	if (!heading) {
		return;
	}
	var title = heading.textContent.trim();
	document.title = title + ' · Watchtower';

	var trigger = event && event.detail && event.detail.elt;
	if (trigger && trigger.closest && trigger.closest('a')) {
		heading.focus({ preventScroll: true });
		heading.scrollIntoView({ block: 'start' });
	}
}

if (document.readyState === 'loading') {
	document.addEventListener('DOMContentLoaded', wtSyncShellHeading, { once: true });
} else {
	wtSyncShellHeading();
}
document.addEventListener('htmx:afterSwap', wtSyncShellHeading);
document.addEventListener('htmx:afterSettle', wtSyncShellHeading);
document.addEventListener('htmx:historyRestore', wtSyncShellHeading);

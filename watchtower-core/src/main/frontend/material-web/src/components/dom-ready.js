// Shared helper for Section C's decorate-only/light-DOM components. A custom element's
// connectedCallback fires the instant the HTML parser inserts its opening tag into an
// already-connected parent - before any of its own children, or any later sibling, have been
// parsed. A component that reads its children (querySelector) or a sibling (getElementById) in
// connectedCallback can silently find nothing on the very first full-page load, even though the
// exact same markup works fine once htmx re-inserts it as part of a boosted swap (that path
// parses a whole fragment before ever attaching it, so every descendant already exists by the
// time connectedCallback fires). Deferring to DOMContentLoaded guarantees the initial document
// has finished parsing first; document.readyState is no longer 'loading' for every subsequent
// (e.g. htmx-driven) connection, so this runs immediately in that case.
export function whenDomReady(callback) {
	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', callback, {once: true});
	} else {
		callback();
	}
}

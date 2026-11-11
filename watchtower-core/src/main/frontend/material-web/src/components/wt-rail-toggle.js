// Material Web migration, Section C (Alpine.js -> Lit): replaces rail-toggle.js's
// Alpine.store('rail'). Desktop icon-rail expand/collapse state, persisted client-side only
// (localStorage). The rail itself (main-sidebar's width, nav-link label visibility, submenu
// flyout-vs-inline presentation) is pure CSS in layout.css, keyed off the wt-rail-expanded
// class this element sets on <html>; this component only owns the toggle/persist/apply logic.
//
// This element fully owns its own rendered content (the <a>/<i> pair) - nothing else needs to
// inject or preserve children inside it - so unlike wt-user-menu/wt-sidebar-nav/wt-mobile-drawer
// it is a LitElement, not a plain decorate-only custom element. See lit-light-element.js for
// why it still renders to light DOM, not a shadow root.
import {html} from 'lit';
import {LitLightElement} from './lit-light-element.js';

const STORAGE_KEY = 'watchtower-rail';

function readStoredExpanded() {
	try {
		return localStorage.getItem(STORAGE_KEY) === 'expanded';
	} catch (e) {
		// Private mode, or site data blocked - collapsed is the default, same fallback as the
		// anti-FOUC inline script in htmlhead.html.
		return false;
	}
}

export class WtRailToggle extends LitLightElement {
	static properties = {
		expanded: {state: true}
	};

	constructor() {
		super();
		this.expanded = readStoredExpanded();
	}

	connectedCallback() {
		super.connectedCallback();
		// Re-applies the same class the anti-FOUC inline script (htmlhead.html) already set
		// before this component's JS loaded - idempotent, and keeps this element as the single
		// source of truth for the class once it's connected.
		this.apply();
	}

	apply() {
		document.documentElement.classList.toggle('wt-rail-expanded', this.expanded);
		// Bug fix, found live-testing Section C: the previous Alpine implementation had the same
		// gap - flyoutStyle() (sidebar-alpine.js) read document.documentElement.classList
		// directly, a plain DOM read Alpine's reactivity has no way to track, so toggling the
		// rail while a collapsed-rail flyout was open left it stuck at its stale fixed-position
		// coordinates, overlapping the newly-expanded rail's own inline labels. wt-sidebar-nav.js
		// listens for this event alongside its own resize handler and recomputes.
		document.dispatchEvent(new CustomEvent('wt-rail-change'));
	}

	toggle() {
		this.expanded = !this.expanded;
		try {
			localStorage.setItem(STORAGE_KEY, this.expanded ? 'expanded' : 'collapsed');
		} catch (e) {
			// Private mode, or site data blocked - the toggle still works for this page view,
			// it just won't persist across a reload.
		}
		this.apply();
	}

	handleClick(event) {
		event.preventDefault();
		this.toggle();
	}

	handleKeydown(event) {
		// A real <a href> activates on Enter natively; Space doesn't activate a link the way it
		// activates a <button>, and this control is semantically a toggle button (role="button"
		// below), so Space needs the same explicit handling a native button gets for free.
		if (event.key === ' ') {
			event.preventDefault();
			this.toggle();
		}
	}

	render() {
		return html`
			<!-- Desktop-only: pins the rail wide, persisted via this element. Hidden below 768px -
			     the mobile drawer has no rail concept, it's just open or closed. -->
			<a href="#" class="rail-toggle d-none d-md-inline" role="button" tabindex="0"
			   aria-pressed=${this.expanded ? 'true' : 'false'}
			   aria-label="Expand or collapse the navigation rail"
			   @click=${(event) => this.handleClick(event)}
			   @keydown=${(event) => this.handleKeydown(event)}>
				<i class="material-icons">${this.expanded ? 'chevron_left' : 'chevron_right'}</i>
			</a>
		`;
	}
}

customElements.define('wt-rail-toggle', WtRailToggle);

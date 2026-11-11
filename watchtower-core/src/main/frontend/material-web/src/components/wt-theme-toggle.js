// Material Web migration, Section C (Alpine.js -> Lit): replaces theme-toggle.js's
// Alpine.store('theme'). Light is the unconditional default (Section B's "Light mode as
// default" work) - only an explicit 'dark' previously saved here changes that. This element
// only re-reads/re-applies the same localStorage key and two-state model tokens.css and the
// anti-FOUC inline script (htmlhead.html) already assume; it must NOT reintroduce a third
// 'auto'/prefers-color-scheme state.
//
// This element fully owns its own rendered content (the <a>/<i>/<span> triple) - nothing else
// needs to inject or preserve children inside it - so it is a LitElement, not a plain
// decorate-only custom element. See lit-light-element.js for why it still renders to light DOM.
import {html} from 'lit';
import {LitLightElement} from './lit-light-element.js';

const STORAGE_KEY = 'watchtower-theme';

function readStoredTheme() {
	try {
		return localStorage.getItem(STORAGE_KEY) === 'dark' ? 'dark' : 'light';
	} catch (e) {
		// Private mode, or site data blocked - light stays the default.
		return 'light';
	}
}

export class WtThemeToggle extends LitLightElement {
	static properties = {
		theme: {state: true}
	};

	constructor() {
		super();
		this.theme = readStoredTheme();
	}

	connectedCallback() {
		super.connectedCallback();
		// Re-applies the same attributes the anti-FOUC inline script (htmlhead.html) already set
		// before this component's JS loaded - idempotent, and keeps this element as the single
		// source of truth for both attributes once it's connected.
		this.apply();
	}

	apply() {
		document.documentElement.setAttribute('data-theme', this.theme);
		// Bootstrap 5 only understands data-bs-theme='dark'/'light' - keep it in lockstep with
		// data-theme, same reasoning as the removed theme-toggle.js.
		document.documentElement.setAttribute('data-bs-theme', this.theme);
	}

	toggle() {
		this.theme = this.theme === 'dark' ? 'light' : 'dark';
		try {
			localStorage.setItem(STORAGE_KEY, this.theme);
		} catch (e) {
			// Private mode, or site data blocked - the toggle still works for this page view, it
			// just won't persist across a reload.
		}
		this.apply();
	}

	// Account menu (UAT walkthrough, 2026-10-16): one "Dark mode" row with a switch that shows the
	// current state, instead of a link whose label flipped between "Dark Mode" and "Light Mode".
	render() {
		const isDark = this.theme === 'dark';
		return html`
			<button type="button" class="dropdown-item wt-theme-item" role="switch" aria-checked=${String(isDark)}
			   @click=${(event) => { event.preventDefault(); this.toggle(); }}>
				<i class="material-icons" aria-hidden="true">dark_mode</i>
				<span>Dark mode</span>
				<span class="wt-switch" aria-hidden="true" data-checked=${String(isDark)}></span>
			</button>
		`;
	}
}

customElements.define('wt-theme-toggle', WtThemeToggle);

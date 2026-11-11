// Cmd+K command palette. This component depends on .main-sidebar's rendered markup shape -
// specifically sidebar.html's real leaf links (`.nav-link[href]:not([href="#"])`), each with a
// child <span> label and a child <i class="material-icons"> icon - see buildResults() below.
// See wt-mobile-drawer.js's own header comment for the same kind of "reaches out to
// .main-sidebar via querySelector" coupling; if sidebar.html's anchor structure changes, this
// component's DOM scan must be updated to match.
//
// A LitLightElement (light DOM, see lit-light-element.js), not a plain decorate-only custom
// element: this component fully owns its own rendered content (the internal <md-dialog>, its
// search <input>, and the result list) - nothing else needs to inject or preserve children
// inside it, same reasoning as wt-searchable-listbox.js.
//
// Overlay: md-dialog, not a hand-rolled overlay like wt-mobile-drawer's scrim. md-dialog is
// backed by a native <dialog> with its own already-shipped focus trap and native Escape ->
// close() handling (dialog.js's handleCancel() -> close(), which fires the 'close' event this
// component listens for below), so there is no separate keydown-based Tab-trap or Escape
// handler to write here, unlike wt-mobile-drawer.js's.
import {html, nothing} from 'lit';
import {repeat} from 'lit/directives/repeat.js';
import {LitLightElement} from './lit-light-element.js';

// Same reasoning as wt-searchable-listbox.js's maxVisible: with every sidebar link as a
// candidate, rendering every match unfiltered would mean a long, slow-to-scan live DOM list.
// A capped list pushes the user toward narrowing their search instead.
const MAX_VISIBLE_RESULTS = 8;

export class WtCommandPalette extends LitLightElement {
	static properties = {
		query: {state: true},
		results: {state: true},
		activeIndex: {state: true}
	};

	constructor() {
		super();
		this.query = '';
		this.results = [];
		this.activeIndex = 0;
		this.triggerEl = null;
		this.handleGlobalKeydown = this.handleGlobalKeydown.bind(this);
	}

	connectedCallback() {
		super.connectedCallback();
		document.addEventListener('keydown', this.handleGlobalKeydown);
	}

	disconnectedCallback() {
		document.removeEventListener('keydown', this.handleGlobalKeydown);
		super.disconnectedCallback();
	}

	handleGlobalKeydown(event) {
		if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
			event.preventDefault();
			this.show();
		}
	}

	get dialogEl() {
		return this.querySelector('md-dialog');
	}

	get inputEl() {
		return this.querySelector('.wt-command-palette__input');
	}

	show() {
		this.triggerEl = document.activeElement instanceof HTMLElement ? document.activeElement : null;
		this.query = '';
		this.activeIndex = 0;
		this.results = this.buildResults();
		this.dialogEl.show();
		// Wait a frame so the dialog's open animation has started before moving focus - acting
		// on a still-animating/offscreen element is unreliable across browsers, same reasoning
		// as wt-mobile-drawer.js's show().
		requestAnimationFrame(() => {
			this.inputEl?.focus();
		});
	}

	// Scan fresh on every show() rather than caching: .main-sidebar lives outside #content and
	// never re-renders on boosted nav (fragments/container.html), so a fresh scan is always
	// current and cheap. Reading the already-rendered DOM (rather than a new endpoint) reuses
	// sidebar.html's own #authorization-driven filtering with no duplicated auth logic - see
	// this file's header comment.
	buildResults() {
		const anchors = document.querySelectorAll('.main-sidebar .nav-link[href]:not([href="#"])');
		return Array.from(anchors).map((anchor) => ({
			label: anchor.querySelector('span')?.textContent.trim() ?? '',
			icon: anchor.querySelector('i.material-icons')?.textContent.trim() ?? '',
			url: anchor.getAttribute('href'),
			target: anchor.getAttribute('target') || '_self'
		}));
	}

	matching() {
		const query = this.query.trim().toLowerCase();
		if (!query) {
			return this.results;
		}
		return this.results.filter((result) => result.label.toLowerCase().includes(query));
	}

	visible() {
		return this.matching().slice(0, MAX_VISIBLE_RESULTS);
	}

	handleDialogClose() {
		if (this.triggerEl) {
			this.triggerEl.focus();
		}
		this.triggerEl = null;
	}

	handleQueryInput(event) {
		this.query = event.target.value;
		// The filtered list can shrink or reorder on every keystroke - clamp back to the top
		// rather than carry over an index that may no longer point at the same result.
		this.activeIndex = 0;
	}

	// Up/Down clamp to the current visible list's bounds rather than wrap - simpler to reason
	// about (no modulo edge cases) and matches wt-searchable-listbox's single-list navigation
	// model; this is a deliberate choice, not an omission.
	handleInputKeydown(event) {
		const visible = this.visible();
		if (event.key === 'ArrowDown') {
			event.preventDefault();
			if (visible.length > 0) {
				this.activeIndex = Math.min(this.activeIndex + 1, visible.length - 1);
			}
		} else if (event.key === 'ArrowUp') {
			event.preventDefault();
			if (visible.length > 0) {
				this.activeIndex = Math.max(this.activeIndex - 1, 0);
			}
		} else if (event.key === 'Enter') {
			event.preventDefault();
			this.navigate(visible[this.activeIndex]);
		}
	}

	// Enter and click-to-navigate share this: respect the result's target the same way
	// sidebar.html's own th:target does for external links, rather than always same-tab.
	navigate(result) {
		if (!result) {
			return;
		}
		if (result.target === '_blank') {
			window.open(result.url, '_blank');
			return;
		}
		window.location.href = result.url;
	}

	render() {
		const matchCount = this.matching().length;
		const visible = this.visible();
		return html`
			<md-dialog @close=${() => this.handleDialogClose()}>
				<div slot="content">
					<input id="wt-command-search" name="commandSearch" type="search"
					       aria-label="Search pages" class="wt-command-palette__input form-control"
					       placeholder="Search pages..." .value=${this.query}
					       @input=${(event) => this.handleQueryInput(event)}
					       @keydown=${(event) => this.handleInputKeydown(event)} autocomplete="off">
					<div class="wt-command-palette__results">
						${repeat(
								visible,
								(result) => result.url,
								(result, index) => html`
									<div class="wt-command-palette__result
									            ${index === this.activeIndex ? 'is-active' : ''}"
									     @click=${() => this.navigate(result)}>
										<i class="material-icons">${result.icon}</i>
										<span>${result.label}</span>
									</div>
								`)}
						${matchCount === 0 ? html`
							<div class="wt-command-palette__empty">No matching pages</div>
						` : nothing}
						${matchCount > MAX_VISIBLE_RESULTS ? html`
							<div class="wt-command-palette__truncated">
								Showing ${MAX_VISIBLE_RESULTS} of ${matchCount} — refine your search
							</div>
						` : nothing}
					</div>
				</div>
			</md-dialog>
		`;
	}
}

customElements.define('wt-command-palette', WtCommandPalette);

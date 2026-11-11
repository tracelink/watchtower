// Material Web migration, Section C (Alpine.js -> Lit): decorates the sidebar account menu's
// x-data="{ open: false }" / @click.outside dropdown scope. This wraps the toggle <a> and the
// .dropdown-menu (Profile link, <wt-theme-toggle>, logout form) as they already come out of
// Thymeleaf - a plain decorate-only custom element, not a LitElement, since a LitElement's
// render() would wipe out that server-rendered content (including the CSRF-carrying logout
// form) the first time it ran. This element only adds open/close behavior over existing
// children, never replaces them.
import {whenDomReady} from './dom-ready.js';

export class WtUserMenu extends HTMLElement {
	connectedCallback() {
		// See dom-ready.js: on the initial full-page parse, this element's own children (the
		// toggle <a>/.dropdown-menu) haven't been parsed yet the instant this callback fires.
		whenDomReady(() => this.init());
	}

	init() {
		this.toggleEl = this.querySelector('.dropdown-toggle');
		this.menuEl = this.querySelector('.dropdown-menu');
		this.toggleEl.setAttribute('aria-expanded', 'false');

		this.handleToggleClick = (event) => {
			event.preventDefault();
			this.setOpen(!this.menuEl.classList.contains('show'));
		};
		this.toggleEl.addEventListener('click', this.handleToggleClick);
		// This menu is owned by this component. Bootstrap's delegated dropdown keyboard
		// handler expects its own toggle and otherwise throws when Escape comes from a row.
		this.handleKeydown = (event) => {
			if (!this.contains(event.target)) return;
			if (!['Escape', 'ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
			const open = this.menuEl.classList.contains('show');
			if (event.key === 'Escape') {
				if (!open) return;
				event.preventDefault();
				event.stopPropagation();
				this.setOpen(false);
				this.toggleEl.focus();
				return;
			}
			event.preventDefault();
			event.stopPropagation();
			this.setOpen(true);
			const items = [...this.menuEl.querySelectorAll('a.dropdown-item, button.dropdown-item')]
				.filter(item => !item.disabled && !item.hidden);
			if (!items.length) return;
			const current = items.indexOf(document.activeElement);
			const index = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1
				: event.key === 'ArrowDown' ? (current + 1) % items.length
				: (current < 0 ? items.length - 1 : (current + items.length - 1) % items.length);
			items[index].focus();
		};
		// Bootstrap delegates in document capture, so handle owned keys before that phase.
		window.addEventListener('keydown', this.handleKeydown, true);

		// Same behavior as the removed @click.outside="open = false": any click landing outside
		// this element closes the menu.
		this.handleDocumentClick = (event) => {
			if (!this.contains(event.target)) {
				this.setOpen(false);
			}
		};
		document.addEventListener('click', this.handleDocumentClick);
	}

	disconnectedCallback() {
		document.removeEventListener('click', this.handleDocumentClick);
		this.toggleEl?.removeEventListener('click', this.handleToggleClick);
		window.removeEventListener('keydown', this.handleKeydown, true);
	}

	setOpen(open) {
		this.menuEl.classList.toggle('show', open);
		this.toggleEl.setAttribute('aria-expanded', open ? 'true' : 'false');
	}
}

customElements.define('wt-user-menu', WtUserMenu);

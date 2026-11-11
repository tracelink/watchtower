// Material Web migration, Section C (Alpine.js -> Lit): replaces mobile-drawer.js's
// Alpine.store('drawer'). Deliberately NOT Bootstrap Offcanvas - its own backdrop +
// body-scroll-lock would need a second htmx:beforeSwap cleanup alongside the one
// loading-indicator.js already runs for modals, risking the same orphaned-backdrop bug that
// fix addresses. .main-sidebar already carries the open/closed transform (layout.css) - this
// just drives that class plus a scrim, a focus trap and Esc, all through one element so there
// is exactly one cleanup surface (hide()) to reason about, not two.
//
// A plain decorate-only custom element, not a LitElement: it wraps the real .wt-drawer-scrim
// div (container.html) as its only child and reaches out to two other Thymeleaf-rendered
// elements via querySelector - the shell's [data-wt-drawer-trigger]
// and the sidebar aside (.main-sidebar) - rather than owning either of their markup itself.
import {whenDomReady} from './dom-ready.js';

const FOCUSABLE_SELECTOR =
	'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])';

export class WtMobileDrawer extends HTMLElement {
	connectedCallback() {
		this.open = false;
		this.triggerEl = null;
		this.keydownHandler = null;

		// See dom-ready.js: on the initial full-page parse, neither this element's own child
		// (.wt-drawer-scrim) nor the trigger ([data-wt-drawer-trigger], which
		// comes later in document order) have been parsed yet the instant this callback fires.
		whenDomReady(() => this.init());
	}

	init() {
		this.scrimEl = this.querySelector('.wt-drawer-scrim');
		this.scrimEl.addEventListener('click', () => this.hide());

		const trigger = document.querySelector('[data-wt-drawer-trigger]');
		if (trigger) {
			trigger.addEventListener('click', (event) => {
				event.preventDefault();
				this.show(trigger);
			});
		}

		// The sidebar lives outside #content (fragments/container.html item 9.1), so a boosted
		// swap never re-renders it - without this, clicking a drawer link would leave the drawer
		// "open" (stale focus trap, scroll lock) on the destination page.
		this.handleBeforeSwap = () => this.hide();
		document.body.addEventListener('htmx:beforeSwap', this.handleBeforeSwap);
	}

	disconnectedCallback() {
		document.body.removeEventListener('htmx:beforeSwap', this.handleBeforeSwap);
	}

	show(triggerEl) {
		if (this.open) {
			return;
		}
		this.triggerEl = triggerEl instanceof HTMLElement ? triggerEl : null;
		this.triggerEl?.setAttribute('aria-expanded', 'true');
		this.open = true;
		document.body.classList.add('wt-drawer-open');
		document.querySelector('.main-sidebar')?.classList.add('open');
		this.scrimEl.classList.add('is-visible');

		this.keydownHandler = (event) => {
			if (event.key === 'Escape') {
				event.preventDefault();
				this.hide();
				return;
			}
			if (event.key !== 'Tab') {
				return;
			}
			const sidebar = document.querySelector('.main-sidebar');
			if (!sidebar) {
				return;
			}
			// Bug fix, found live-testing Section C (a pre-existing gap in the Alpine version
			// too - FOCUSABLE_SELECTOR is unfiltered there as well): a collapsed .wt-nav-section
			// uses visibility:hidden to keep itself out of the tab order (see sidebar.html's
			// comment), but every link inside it still matches FOCUSABLE_SELECTOR - the last
			// DOM-order match is very often one of these, and .focus() on a visibility:hidden
			// element is a silent no-op, so Shift+Tab off the first item never actually wrapped
			// to a real last item in the common "everything collapsed" case.
			const focusables = Array.from(sidebar.querySelectorAll(FOCUSABLE_SELECTOR))
					.filter((el) => {
						const style = getComputedStyle(el);
						return style.visibility !== 'hidden' && style.display !== 'none';
					});
			if (focusables.length === 0) {
				return;
			}
			const first = focusables[0];
			const last = focusables[focusables.length - 1];
			// Standard dialog focus-trap wrap: Shift+Tab off the first element goes to the
			// last, Tab off the last goes back to the first.
			if (event.shiftKey && document.activeElement === first) {
				event.preventDefault();
				last.focus();
			} else if (!event.shiftKey && document.activeElement === last) {
				event.preventDefault();
				first.focus();
			}
		};
		document.addEventListener('keydown', this.keydownHandler);

		// Wait a frame so the open transform has started before moving focus - acting on a
		// still-offscreen element is unreliable across browsers, same reasoning as the
		// DataTables/modal fixes elsewhere in this migration.
		requestAnimationFrame(() => {
			const sidebar = document.querySelector('.main-sidebar');
			const focusable = sidebar && sidebar.querySelector(FOCUSABLE_SELECTOR);
			if (focusable) {
				focusable.focus();
			}
		});
	}

	hide() {
		if (!this.open) {
			return;
		}
		this.open = false;
		document.body.classList.remove('wt-drawer-open');
		document.querySelector('.main-sidebar')?.classList.remove('open');
		this.scrimEl.classList.remove('is-visible');
		if (this.keydownHandler) {
			document.removeEventListener('keydown', this.keydownHandler);
			this.keydownHandler = null;
		}
		if (this.triggerEl) {
			this.triggerEl.setAttribute('aria-expanded', 'false');
			this.triggerEl.focus();
		}
		this.triggerEl = null;
	}
}

customElements.define('wt-mobile-drawer', WtMobileDrawer);

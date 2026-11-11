// Material Web migration, Section C (Alpine.js -> Lit): replaces sidebar-alpine.js's
// sidebarNav(). Sidebar collapse/expand state and active-link highlighting over the real
// Thymeleaf-rendered nav tree (sidebar.html's th:each-generated <li>/<a>/<div
// class="wt-nav-section"> markup) - a plain decorate-only custom element, not a LitElement,
// since this must operate on that existing server-rendered markup, never re-template it.
//
// Since fragments/sidebar.html lives outside #content (item 9.1), an htmx-boosted swap never
// re-renders this element's children - a one-shot connectedCallback() would leave the "active"
// highlight and open/closed section state stale after the first boosted click, so this
// recomputes the active link on every htmx:afterSettle too, not just on connect.
import {whenDomReady} from './dom-ready.js';

export class WtSidebarNav extends HTMLElement {
	connectedCallback() {
		this.openSections = {};
		this.activeHref = null;

		this.handleClick = (event) => {
			const link = event.target.closest('a.nav-link[data-section-index]');
			if (!link || !this.contains(link)) {
				const destination = event.target.closest('a.nav-link[href]:not([href="#"])');
				if (destination && this.contains(destination)) {
					this.closeAllSectionsExcept();
				}
				return;
			}
			event.preventDefault();
			this.toggleSection(link.dataset.sectionIndex);
		};
		this.addEventListener('click', this.handleClick);
		this.handleDocumentClick = (event) => {
			if (!this.contains(event.target)) {
				this.closeAllSectionsExcept();
			}
		};
		document.addEventListener('click', this.handleDocumentClick);
		this.handleKeydown = (event) => {
			if (event.key !== 'Escape') {
				return;
			}
			const openIdx = Object.keys(this.openSections).find((idx) => this.isOpen(idx));
			if (openIdx === undefined) {
				return;
			}
			event.preventDefault();
			this.closeAllSectionsExcept();
			this.querySelector(`a.nav-link[data-section-index="${openIdx}"]`)?.focus();
		};
		document.addEventListener('keydown', this.handleKeydown);

		// Recomputes every currently-open section's flyout position, same reasoning as the
		// removed resizeTick property: window.innerWidth isn't reactive, so without this,
		// resizing across the 768px breakpoint while a flyout is open leaves its last-computed
		// desktop position:fixed coordinates stuck in place at the new (e.g. mobile) width.
		this.handleResize = () => this.reapplyOpenFlyouts();
		window.addEventListener('resize', this.handleResize);

		// Bug fix, found live-testing Section C (a pre-existing gap in the Alpine version too -
		// see wt-rail-toggle.js's apply()): the rail's own expand/collapse state changing left any
		// section that was open before the toggle stuck open, just repositioned into (or out of)
		// flyout mode - e.g. a submenu opened inline while the rail was expanded reappeared as an
		// overlapping flyout the instant the rail collapsed, with no click reopening it. Closing
		// everything on a rail change (closeAllSectionsExcept() with no exception index closes
		// every open section) matches the same single-section-open accordion behavior toggling a
		// section already enforces.
		this.handleRailChange = () => this.closeAllSectionsExcept();
		document.addEventListener('wt-rail-change', this.handleRailChange);

		this.handleAfterSettle = () => {
			this.closeAllSectionsExcept();
			this.refreshActive();
		};
		document.body.addEventListener('htmx:afterSettle', this.handleAfterSettle);

		// See dom-ready.js: on the initial full-page parse, this element's own children (the
		// th:each-rendered <li>/<a> tree) haven't been parsed yet the instant this callback
		// fires, so the very first refreshActive() would silently find zero nav links.
		whenDomReady(() => this.refreshActive());
	}

	disconnectedCallback() {
		this.removeEventListener('click', this.handleClick);
		document.removeEventListener('click', this.handleDocumentClick);
		document.removeEventListener('keydown', this.handleKeydown);
		window.removeEventListener('resize', this.handleResize);
		document.removeEventListener('wt-rail-change', this.handleRailChange);
		document.body.removeEventListener('htmx:afterSettle', this.handleAfterSettle);
	}

	isOpen(idx) {
		return !!this.openSections[idx];
	}

	// Bug fix: neither toggleSection() nor refreshActive() ever closed any OTHER section
	// before opening one - openSections only ever grew, never shrank, since this element lives
	// outside #content and is never destroyed/recreated across htmx-boosted navigations. After
	// visiting one page in each of several multi-link groups, every one of those groups' flyouts
	// stayed permanently open at once; in collapsed-rail mode they all share the same
	// getBoundingClientRect().right x-coordinate (every top-level trigger sits in the same
	// fixed-width rail column), so several stuck-open flyouts rendered stacked directly on top
	// of one another, reading as one merged panel. Single-section-open accordion behavior (like
	// most sidebar navs, and matching "the submenu should be collapsed") requires closing every
	// other index whenever one opens.
	closeAllSectionsExcept(exceptIdx) {
		for (const idx of Object.keys(this.openSections)) {
			if (idx !== String(exceptIdx) && this.isOpen(idx)) {
				this.openSections[idx] = false;
				this.applySection(idx);
			}
		}
	}

	toggleSection(idx) {
		const willOpen = !this.isOpen(idx);
		if (willOpen) {
			this.closeAllSectionsExcept(idx);
		}
		this.openSections[idx] = willOpen;
		this.applySection(idx);
	}

	applySection(idx) {
		const link = this.querySelector(`a.nav-link[data-section-index="${idx}"]`);
		const panel = this.querySelector(`[data-section-index="${idx}"].wt-nav-section`);
		if (link) {
			link.setAttribute('aria-expanded', this.isOpen(idx) ? 'true' : 'false');
		}
		if (panel) {
			panel.classList.toggle('is-open', this.isOpen(idx));
			this.applyFlyoutStyle(panel, idx);
		}
	}

	reapplyOpenFlyouts() {
		for (const idx of Object.keys(this.openSections)) {
			if (this.isOpen(idx)) {
				const panel = this.querySelector(`[data-section-index="${idx}"].wt-nav-section`);
				if (panel) {
					this.applyFlyoutStyle(panel, idx);
				}
			}
		}
	}

	// Bug fix, found live-testing Phase 11 Section D: .nav-wrapper needs overflow-y:auto for a
	// long nav list, and overflow-x:hidden alongside it (any other value pairs badly with auto
	// per the CSS overflow spec) clips a collapsed-rail flyout's position:absolute box the
	// instant it extends past the 64px rail width - the .wt-nav-section rendered, but
	// invisibly, clipped to zero width. position:fixed is not clipped by an ancestor's overflow
	// (only by an ancestor establishing its own containing block via transform/will-change/
	// filter/perspective/contain - .main-sidebar's will-change:transform is the nearest one
	// here, and it sits at the viewport's own top-left, so viewport-relative
	// getBoundingClientRect() coordinates still land in the right place).
	applyFlyoutStyle(panel, idx) {
		if (!this.isOpen(idx)) {
			panel.style.position = '';
			panel.style.top = '';
			panel.style.left = '';
			return;
		}
		if (document.documentElement.classList.contains('wt-rail-expanded')
				|| window.innerWidth < 768) {
			panel.style.position = '';
			panel.style.top = '';
			panel.style.left = '';
			return;
		}
		const trigger = panel.parentElement.querySelector(
				`a.nav-link[data-section-index="${idx}"]`);
		if (!trigger) {
			return;
		}
		const rect = trigger.getBoundingClientRect();
		panel.style.position = 'fixed';
		panel.style.top = rect.top + 'px';
		panel.style.left = rect.right + 'px';
	}

	// Finds the nav link whose href is the longest prefix match of the current path - same
	// "walk the path up to the last /" approach the old sidebar.js used, so a page like
	// /scan/results/all still highlights the /scan/results/all link exactly, and a page with no
	// exact link (e.g. a report detail) falls back to its closest ancestor.
	refreshActive() {
		const links = Array.from(this.querySelectorAll('a.nav-link[href]'));
		// A page can name its sidebar entry when its URL's closest ancestor is the wrong one:
		// /scan/report/1 would otherwise highlight New Scan (/scan) instead of Results.
		const hint = document.querySelector('#content [data-nav-active]');
		let path = hint ? hint.getAttribute('data-nav-active') : window.location.pathname;
		let match = null;
		while (!match && path !== '') {
			match = links.find((a) => a.getAttribute('href') === path) || null;
			path = path.substring(0, path.lastIndexOf('/'));
		}
		this.activeHref = match ? match.getAttribute('href') : null;
		for (const link of links) {
			link.classList.toggle('active', this.activeHref !== null
					&& link.getAttribute('href') === this.activeHref);
		}
		if (match) {
			const panel = match.closest('[data-section-index]');
			if (panel) {
				const idx = panel.dataset.sectionIndex;
				const inlineSection = document.documentElement.classList.contains('wt-rail-expanded')
					|| window.innerWidth < 768;
				if (inlineSection && !this.isOpen(idx)) {
					this.closeAllSectionsExcept(idx);
					this.openSections[idx] = true;
					this.applySection(idx);
				} else if (!inlineSection && this.isOpen(idx)) {
					this.openSections[idx] = false;
					this.applySection(idx);
				}
			}
		}
	}
}

customElements.define('wt-sidebar-nav', WtSidebarNav);

// Bug fix, reported directly by the user: Phase 11 Section B's selectpicker -> .form-select
// conversion left #rulesPicker (rules/rulesets.html) and #inheritedRulesetIds as a plain
// <select multiple size="8"> with no search - unusable for #rulesPicker, which can carry over a
// thousand individual rule options. This renders a searchable checkbox list and keeps the real
// select (a sibling outside this element, untouched) in sync, so the POST each form sends is
// unchanged. Originally built as an Alpine.js component (searchableListbox()); this is its
// Section C (Alpine.js -> Lit) replacement.
//
// The real <select> stays in the DOM, visually hidden (aria-hidden, tabindex="-1" - see the
// visually-hidden rule this depends on in components.css) with its original name/form/id
// attributes untouched. Selecting a row here sets the matching real <option>'s .selected flag
// directly and fires a change event, so nothing downstream needs to know a hidden native select
// is even involved.
//
// Rendering is capped per group (maxVisible) regardless of how many options match the current
// search - with 1142 real options, rendering all matches unfiltered would mean 1142 live DOM
// checkbox rows. A capped list with a "showing N of M" hint stays fast and pushes the user
// toward the search box, which is the whole point of this component.
//
// This element fully owns its own rendered content (header/count, search input, grouped
// checkbox list) - nothing else needs to inject or preserve children inside it - so it is a
// LitElement, not a plain decorate-only custom element. The real <select> it reads from and
// writes back to lives OUTSIDE this element as a sibling, never as a child, so lit-html's
// rendering of this element's own content never touches it.
import {html, nothing} from 'lit';
import {repeat} from 'lit/directives/repeat.js';
import {whenDomReady} from './dom-ready.js';
import {LitLightElement} from './lit-light-element.js';

export class WtSearchableListbox extends LitLightElement {
	static properties = {
		selectId: {attribute: 'select-id'},
		label: {},
		searchPlaceholder: {attribute: 'search-placeholder'},
		emptyText: {attribute: 'empty-text'},
		maxVisible: {attribute: 'max-visible', type: Number},
		query: {state: true},
		groups: {state: true}
	};

	constructor() {
		super();
		this.maxVisible = 100;
		this.query = '';
		this.groups = [];
	}

	connectedCallback() {
		super.connectedCallback();
		// See dom-ready.js: this element is placed BEFORE its real <select> sibling in every
		// call site's markup, so on the initial full-page parse that sibling hasn't been parsed
		// yet the instant this callback fires - document.getElementById would return null.
		whenDomReady(() => this.init());
	}

	init() {
		this.selectEl = document.getElementById(this.selectId);
		this.groups = Array.from(this.selectEl.querySelectorAll('optgroup')).map((group) => ({
			label: group.label,
			options: Array.from(group.querySelectorAll('option')).map((option) => ({
				value: option.value,
				text: option.textContent.trim(),
				selected: option.selected
			}))
		}));
	}

	get selectedCount() {
		return this.groups.reduce(
				(total, group) => total + group.options.filter((option) => option.selected).length,
				0);
	}

	matching(group) {
		const query = this.query.trim().toLowerCase();
		if (!query) {
			return group.options;
		}
		return group.options.filter((option) => option.text.toLowerCase().includes(query));
	}

	visible(group) {
		return this.matching(group).slice(0, this.maxVisible);
	}

	hasNoMatches() {
		return this.groups.every((group) => this.matching(group).length === 0);
	}

	toggleOption(option) {
		option.selected = !option.selected;
		const realOption = Array.from(this.selectEl.options)
				.find((candidate) => candidate.value === option.value);
		if (realOption) {
			realOption.selected = option.selected;
		}
		this.selectEl.dispatchEvent(new Event('change', {bubbles: true}));
		this.requestUpdate();
	}

	render() {
		const searchInputId = `${this.selectId}Search`;
		return html`
			<div class="wt-searchable-listbox__header">
				<label for=${searchInputId} class="mb-0">${this.label}</label>
				<span class="wt-searchable-listbox__count">${this.selectedCount} selected</span>
			</div>
			<input type="search" id=${searchInputId} class="form-control mb-2"
			       placeholder=${this.searchPlaceholder} .value=${this.query}
			       @input=${(event) => { this.query = event.target.value; }} autocomplete="off">
			<div class="scrollable-6 wt-searchable-listbox__body">
				${repeat(
						this.groups.filter((group) => this.matching(group).length > 0),
						(group) => group.label,
						(group) => html`
							<div>
								<div class="wt-searchable-listbox__group-label">${group.label}</div>
								${repeat(
										this.visible(group),
										(option) => option.value,
										(option) => html`
											<div class="form-check">
												<input class="form-check-input" type="checkbox"
												       id=${`${this.selectId}-${option.value}`}
												       .checked=${option.selected}
												       @change=${() => this.toggleOption(option)}>
												<label class="form-check-label"
												       for=${`${this.selectId}-${option.value}`}>${option.text}</label>
											</div>
										`)}
								${this.matching(group).length > this.maxVisible ? html`
									<div class="wt-searchable-listbox__truncated">
										Showing ${this.maxVisible} of ${this.matching(group).length}
										— refine your search
									</div>
								` : nothing}
							</div>
						`)}
				${this.hasNoMatches() ? html`
					<div class="wt-searchable-listbox__empty">${this.emptyText}</div>
				` : nothing}
			</div>
		`;
	}
}

customElements.define('wt-searchable-listbox', WtSearchableListbox);

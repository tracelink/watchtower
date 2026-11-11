// Material Web migration, Section C (Alpine.js -> Lit): shared base for every app-authored
// component below. Light DOM, not shadow DOM - global stylesheets (components.css/layout.css)
// never cross a shadow boundary, and this app has exactly one design-token CSS system every
// page is already styled from; a real shadow root would silently stop inheriting it. Every
// component built on this fully owns its own rendered content (nothing else needs to inject
// children into it) - anything that must keep Thymeleaf-rendered children intact instead uses
// a plain, non-Lit decorate-only custom element (see wt-user-menu.js/wt-sidebar-nav.js/
// wt-mobile-drawer.js), since a LitElement's render() would silently wipe those children out
// the first time it ran - lit-html manages its container's content directly.
import {LitElement} from 'lit';

export class LitLightElement extends LitElement {
	createRenderRoot() {
		return this;
	}
}

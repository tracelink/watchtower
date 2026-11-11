// Headless smoke test for the built Material Web bundle, using jsdom in place of a real
// browser (no browser is available in this environment). Not a substitute for manual
// verification, but catches gross breakage - a build that silently fails to register a
// custom element (the exact bug class the CDN import-map pilot hit for 'tslib') would
// otherwise only surface as unstyled plain text in a real browser.
const {JSDOM} = require("jsdom");
const fs = require("fs");
const path = require("path");
const assert = require("assert");

const dom = new JSDOM("<!doctype html><html><body></body></html>");

// Copy the whole jsdom window surface onto Node's global - Lit's feature-detection touches
// a wide, version-varying set of DOM globals (Document, CSSStyleSheet, ShadowRoot, etc.), so
// hand-picking properties one at a time chases a moving target. This mirrors the standard
// "jsdom as global environment" polyfill technique.
for (const prop of Object.getOwnPropertyNames(dom.window)) {
	if (typeof global[prop] === "undefined") {
		global[prop] = dom.window[prop];
	}
}
global.window = dom.window;
global.document = dom.window.document;
global.ResizeObserver = class {
	observe() {}
	unobserve() {}
	disconnect() {}
};
// jsdom doesn't implement matchMedia; Material Web's ripple checks
// "forced-colors: active" at module-evaluation time.
global.matchMedia = dom.window.matchMedia = () => ({
	matches: false,
	addListener() {},
	removeListener() {},
	addEventListener() {},
	removeEventListener() {},
});

const bundlePath = path.join(
	__dirname,
	"../../resources/static/scripts/material-web-bundle.js"
);
const bundleSource = fs.readFileSync(bundlePath, "utf8");
dom.window.eval(bundleSource);

const expectedTags = [
	"md-dialog",
	"md-filled-button",
	"md-text-button",
	"md-outlined-button",
	"md-outlined-text-field",
	"md-checkbox",
	"md-outlined-select",
	"md-select-option",
	"wt-theme-toggle",
	"wt-rail-toggle",
	"wt-user-menu",
	"wt-sidebar-nav",
	"wt-mobile-drawer",
	"wt-searchable-listbox",
	"wt-command-palette",
];

for (const tag of expectedTags) {
	const ctor = dom.window.customElements.get(tag);
	assert.ok(ctor, `expected customElements.get('${tag}') to be defined, got ${ctor}`);
	console.log(`PASS: ${tag} registered`);
}

console.log("\nAll smoke tests passed.");
process.exit(0);

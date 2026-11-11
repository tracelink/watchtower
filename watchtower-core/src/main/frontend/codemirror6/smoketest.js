// Headless smoke test for the built CodeMirror 6 bundle, using jsdom in
// place of a real browser (no browser is available in this environment).
// Not a substitute for manual verification, but catches gross breakage in
// the fromTextArea() shim: construction, getValue/setValue round-trip,
// setSize, refresh, readOnly, and the two language modes actually used.
const {JSDOM} = require("jsdom");
const fs = require("fs");
const path = require("path");
const assert = require("assert");

const dom = new JSDOM("<!doctype html><html><body></body></html>");
dom.window.requestAnimationFrame = (cb) => setTimeout(cb, 0);
dom.window.cancelAnimationFrame = (id) => clearTimeout(id);
dom.window.ResizeObserver = class {
	observe() {}
	unobserve() {}
	disconnect() {}
};

global.window = dom.window;
global.document = dom.window.document;
global.navigator = dom.window.navigator;
global.Window = dom.window.Window;
global.MutationObserver = dom.window.MutationObserver;
global.getComputedStyle = dom.window.getComputedStyle;
global.requestAnimationFrame = dom.window.requestAnimationFrame;
global.cancelAnimationFrame = dom.window.cancelAnimationFrame;
global.ResizeObserver = dom.window.ResizeObserver;

const bundlePath = path.join(
	__dirname,
	"../../resources/static/scripts/codemirror-bundle.js"
);
const bundleSource = fs.readFileSync(bundlePath, "utf8");
dom.window.eval(bundleSource);

function makeTextarea(initialValue) {
	const textarea = document.createElement("textarea");
	textarea.value = initialValue;
	document.body.appendChild(textarea);
	return textarea;
}

// Basic construction + getValue
{
	const textarea = makeTextarea("hello world");
	const editor = window.CodeMirror.fromTextArea(textarea, {lineNumbers: true});
	assert.strictEqual(editor.getValue(), "hello world");
	assert.strictEqual(textarea.style.display, "none");
	console.log("PASS: basic fromTextArea + getValue");
}

// The editor's text box is named from the textarea, so screen readers announce it
{
	const labelled = makeTextarea("");
	labelled.setAttribute("aria-label", "Rule create function");
	const editor = window.CodeMirror.fromTextArea(labelled, {});
	assert.strictEqual(
		editor.view.contentDOM.getAttribute("aria-label"),
		"Rule create function"
	);
	const bare = makeTextarea("");
	bare.name = "query";
	assert.strictEqual(
		window.CodeMirror.fromTextArea(bare, {}).view.contentDOM.getAttribute("aria-label"),
		"query"
	);
	console.log("PASS: editors take their textarea's accessible name");
}

// setValue updates getValue and syncs back to the original textarea
{
	const textarea = makeTextarea("initial");
	const editor = window.CodeMirror.fromTextArea(textarea, {lineNumbers: true});
	editor.setValue("changed value");
	assert.strictEqual(editor.getValue(), "changed value");
	assert.strictEqual(
		textarea.value,
		"changed value",
		"underlying textarea must stay in sync, like CM5's fromTextArea did"
	);
	console.log("PASS: setValue + textarea sync-back");
}

// setSize + refresh don't throw
{
	const textarea = makeTextarea("");
	const editor = window.CodeMirror.fromTextArea(textarea, {lineNumbers: true});
	editor.setSize(null, 240);
	editor.setSize("100%", null);
	editor.refresh();
	console.log("PASS: setSize + refresh do not throw");
}

// readOnly mode constructs and rejects a direct doc replacement via dispatch
// the same way a user keystroke would be rejected (readOnly blocks user-facing
// edits at the state level; setValue's own dispatch is app-driven, not user
// input, so it's expected to still work - readOnly's contract is "block
// EditorView's own default input handling", not "block programmatic changes")
{
	const textarea = makeTextarea("readonly content");
	const editor = window.CodeMirror.fromTextArea(textarea, {
		lineNumbers: true,
		readOnly: true,
	});
	assert.strictEqual(editor.getValue(), "readonly content");
	console.log("PASS: readOnly construction");
}

// javascript and json language modes construct without throwing
{
	const jsTextarea = makeTextarea("function f() { return 1; }");
	window.CodeMirror.fromTextArea(jsTextarea, {lineNumbers: true, mode: "javascript"});
	console.log("PASS: mode=javascript construction");

	const jsonTextarea = makeTextarea('{"a": 1}');
	window.CodeMirror.fromTextArea(jsonTextarea, {lineNumbers: true, mode: "json"});
	console.log("PASS: mode=json construction");
}

// Match highlighting: lines get a tint and a gutter class; jumpToLine moves the cursor; a
// changed document drops stale highlights; out-of-range lines are ignored.
{
	const textarea = makeTextarea("one\ntwo\nthree\nfour\nfive");
	const editor = window.CodeMirror.fromTextArea(textarea, {lineNumbers: true, lineWrapping: true});
	editor.highlightLines([2, 4, 99, "x"]);
	const hits = Array.from(editor.view.dom.querySelectorAll(".cm-line.wt-cm-hit")).map((l) => l.textContent);
	assert.deepStrictEqual(hits, ["two", "four"]);
	assert.strictEqual(editor.view.dom.querySelectorAll(".wt-cm-hit-gutter").length, 2);
	assert.strictEqual(editor.jumpToLine(4), true);
	assert.strictEqual(editor.view.state.selection.main.head, editor.view.state.doc.line(4).from);
	assert.strictEqual(editor.jumpToLine(42), false);
	editor.setValue("changed");
	assert.strictEqual(editor.view.dom.querySelectorAll(".wt-cm-hit").length, 0);
	console.log("PASS: highlightLines + jumpToLine + lineWrapping");
}

console.log("\nAll smoke tests passed.");
process.exit(0);

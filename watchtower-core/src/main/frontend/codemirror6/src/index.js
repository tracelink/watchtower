// Minimal CodeMirror 5 -> 6 compatibility shim.
//
// This exposes a global `CodeMirror.fromTextArea(textarea, options)` matching
// only the small subset of the CodeMirror 5 API actually used by Watchtower's
// rule designer scripts (pmd-designer.js, eslint-designer.js, eslint-editor.js,
// json-designer.js, regex-designer.js) - verified by reading all five files:
//
//   options: lineNumbers, mode ("javascript" | "json" | unset), readOnly, lineWrapping
//   methods: getValue(), setValue(value), setSize(width, height), refresh()
//
// Plus two Watchtower additions for the rule designers' match chips (UAT walkthrough,
// 2026-10-16): highlightLines([1-based line numbers]) tints those lines and marks their gutter,
// and jumpToLine(n) moves the cursor there and scrolls it into view.
//
// This exists so the migration to CodeMirror 6 (which dropped fromTextArea
// entirely in favor of an EditorView/EditorState/extensions model) doesn't
// require touching any of those five designer scripts.
import {EditorState, RangeSetBuilder, StateEffect, StateField} from "@codemirror/state";
import {
	Decoration,
	EditorView,
	GutterMarker,
	gutterLineClass,
	keymap,
	lineNumbers as lineNumbersExt,
} from "@codemirror/view";
import {defaultKeymap, history, historyKeymap} from "@codemirror/commands";
import {javascript} from "@codemirror/lang-javascript";
import {json} from "@codemirror/lang-json";

function languageExtension(mode) {
	if (mode === "javascript") {
		return javascript();
	}
	if (mode === "json") {
		return json();
	}
	return [];
}

// Matched lines: a line decoration (tint) and a gutter class (dot), both from one field holding
// the sorted line starts. Lines past the end of the document are ignored.
const setHits = StateEffect.define();
const hitLineDecoration = Decoration.line({class: "wt-cm-hit"});
class HitGutterMarker extends GutterMarker {}
HitGutterMarker.prototype.elementClass = "wt-cm-hit-gutter";
const hitGutterMarker = new HitGutterMarker();

const hitStarts = StateField.define({
	create() {
		return [];
	},
	update(starts, transaction) {
		for (const effect of transaction.effects) {
			if (effect.is(setHits)) {
				return effect.value;
			}
		}
		return transaction.docChanged ? [] : starts;
	},
	provide: (field) => [
		EditorView.decorations.from(field, (starts) => {
			const builder = new RangeSetBuilder();
			starts.forEach((from) => builder.add(from, from, hitLineDecoration));
			return builder.finish();
		}),
		gutterLineClass.from(field, (starts) => {
			const builder = new RangeSetBuilder();
			starts.forEach((from) => builder.add(from, from, hitGutterMarker));
			return builder.finish();
		}),
	],
});

function lineStarts(doc, lines) {
	const numbers = Array.from(new Set((lines || []).map(Number)))
		.filter((n) => Number.isInteger(n) && n >= 1 && n <= doc.lines)
		.sort((a, b) => a - b);
	return numbers.map((n) => doc.line(n).from);
}

function toCssLength(value) {
	if (value === null || value === undefined) {
		return null;
	}
	return typeof value === "number" ? value + "px" : value;
}

// The editor's text box has no name of its own; it takes the textarea's (aria-label, an associated
// <label>, or its name) so screen readers announce it.
function accessibleName(textarea, options) {
	const label = textarea.labels && textarea.labels[0];
	return options.ariaLabel || textarea.getAttribute("aria-label")
		|| (label && label.textContent.trim()) || textarea.name || "Code editor";
}

function fromTextArea(textarea, options) {
	options = options || {};

	const extensions = [
		history(),
		keymap.of([...defaultKeymap, ...historyKeymap]),
		languageExtension(options.mode),
		hitStarts,
		EditorView.contentAttributes.of({"aria-label": accessibleName(textarea, options)}),
		EditorView.updateListener.of((update) => {
			if (update.docChanged) {
				textarea.value = update.state.doc.toString();
			}
		}),
	];
	if (options.lineNumbers) {
		extensions.push(lineNumbersExt());
	}
	if (options.lineWrapping) {
		extensions.push(EditorView.lineWrapping);
	}
	if (options.readOnly) {
		extensions.push(EditorState.readOnly.of(true));
		extensions.push(EditorView.editable.of(false));
	}

	const state = EditorState.create({doc: textarea.value, extensions});
	const view = new EditorView({state});

	textarea.parentNode.insertBefore(view.dom, textarea);
	textarea.style.display = "none";

	return {
		view: view,
		getValue: function () {
			return view.state.doc.toString();
		},
		setValue: function (value) {
			view.dispatch({
				changes: {from: 0, to: view.state.doc.length, insert: value},
			});
		},
		setSize: function (width, height) {
			const cssWidth = toCssLength(width);
			const cssHeight = toCssLength(height);
			if (cssWidth !== null) {
				view.dom.style.width = cssWidth;
			}
			if (cssHeight !== null) {
				view.dom.style.height = cssHeight;
				view.scrollDOM.style.height = cssHeight;
			}
		},
		refresh: function () {
			view.requestMeasure();
		},
		highlightLines: function (lines) {
			view.dispatch({effects: setHits.of(lineStarts(view.state.doc, lines))});
		},
		jumpToLine: function (line) {
			const n = Number(line);
			if (!Number.isInteger(n) || n < 1 || n > view.state.doc.lines) {
				return false;
			}
			const from = view.state.doc.line(n).from;
			view.dispatch({
				selection: {anchor: from},
				effects: EditorView.scrollIntoView(from, {y: "center"}),
			});
			view.focus();
			return true;
		},
	};
}

window.CodeMirror = {fromTextArea: fromTextArea};

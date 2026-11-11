"""Parse one bounded source file as data. Never import or execute repository code."""
import importlib
import importlib.metadata
import json
import sys
from pathlib import Path

PINNED = {"java": ("tree_sitter_java", "0.23.5"),
          "python": ("tree_sitter_python", "0.25.0"),
          "javascript": ("tree_sitter_javascript", "0.25.0"),
          "typescript": ("tree_sitter_typescript", "0.23.2"),
          "tsx": ("tree_sitter_typescript", "0.23.2")}
DEFINITIONS = {"class_declaration", "interface_declaration", "enum_declaration", "record_declaration",
               "method_declaration", "constructor_declaration", "function_declaration", "function_definition",
               "class_definition", "method_definition", "arrow_function"}
IDENTIFIERS = {"identifier", "type_identifier", "property_identifier"}


def analyze(path, language, operation, symbol):
    module_name, version = PINNED[language]
    if importlib.metadata.version("tree-sitter") != "0.25.2" or importlib.metadata.version(module_name.replace("_", "-")) != version:
        raise ValueError("Parser version mismatch")
    from tree_sitter import Language, Parser
    module = importlib.import_module(module_name)
    grammar = module.language_typescript() if language == "typescript" else module.language_tsx() if language == "tsx" else module.language()
    parser = Parser(Language(grammar))
    data = Path(path).read_bytes()
    if len(data) > 1024 * 1024:
        raise ValueError("Input limit")
    tree = parser.parse(data)
    entries, stack, visited, truncated = [], [(tree.root_node, None)], 0, False
    while stack:
        node, enclosing = stack.pop()
        visited += 1
        if visited > 100_000:
            truncated = True
            break
        name_node = node.child_by_field_name("name")
        if node.type == "arrow_function" and node.parent and node.parent.type == "variable_declarator":
            name_node = node.parent.child_by_field_name("name")
        if node.type in DEFINITIONS and name_node:
            name = data[name_node.start_byte:name_node.end_byte].decode("utf-8")[:100]
            if operation == "outline" or operation == "symbols" and symbol in name:
                entries.append({"name": name, "kind": node.type, "line": node.start_point.row + 1,
                                "end_line": node.end_point.row + 1, "enclosing": enclosing})
            enclosing = name
        elif operation == "references" and node.type in IDENTIFIERS:
            name = data[node.start_byte:node.end_byte].decode("utf-8")
            if name == symbol:
                parent = node.parent
                declaration = parent and parent.type in DEFINITIONS and parent.child_by_field_name("name") == node
                if not declaration:
                    entries.append({"name": name, "kind": "approximate_reference", "line": node.start_point.row + 1,
                                    "enclosing": enclosing})
        if len(entries) >= 100:
            truncated = bool(stack) or bool(node.named_children)
            break
        stack.extend((child, enclosing) for child in reversed(node.named_children))
    return {"language": language, "parser": "tree-sitter", "parser_version": "0.25.2",
            "grammar_version": version, "syntax_errors": tree.root_node.has_error, "truncated": truncated,
            "approximate": True, "entries": entries,
            "limitation": "Syntax only; unresolved/dynamic references and callers may be missing. Absence does not prove unreachable code. No framework sanitizer behavior is established."}


if __name__ == "__main__":
    try:
        print(json.dumps(analyze(*sys.argv[1:]), ensure_ascii=True))
    except Exception:
        # Parser/OS exceptions can include source or installation paths.
        print(json.dumps({"unavailable": True, "limitation": "Pinned parser unavailable, unsupported syntax, or input limit."}))
        sys.exit(1)

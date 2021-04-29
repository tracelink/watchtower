package com.tracelink.appsec.module.pmd.designer;

import net.sourceforge.pmd.lang.ast.Node;

import java.util.function.BiFunction;

/**
 * A general-purpose AST Generation class. Does not have any language-specific
 * instructions and attempts to dump all nodes and all attributes
 *
 * @author csmith
 */
public class PMDASTGenerator {
	private final String prefix;

	public PMDASTGenerator(String prefix) {
		this.prefix = prefix;
	}

	/**
	 * Visitor pattern to hit all nodes in the tree
	 *
	 * @param node         the current node the visitor is visiting
	 * @param data         the prefix data for the node
	 * @param functionCall the call to make while visiting this node
	 * @return the prefix we've used at this node
	 */
	public Object visit(Node node, String data, BiFunction<Node, String, ?> functionCall) {
		functionCall.apply(node, data);
		node.children().forEach(child -> visit(child, data + prefix, functionCall));
		return data;
	}
}

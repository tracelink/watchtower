package com.tracelink.appsec.module.pmd.designer;

import net.sourceforge.pmd.lang.ast.Node;
import net.sourceforge.pmd.lang.ast.xpath.Attribute;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * This model is used to translate PMD Nodes to something easier to handle in
 * Thymeleaf for the AST dump
 *
 * @author csmith
 */
public class DesignerASTModel {
	private String name;
	private List<String> attributes = new ArrayList<String>();

	public DesignerASTModel(String prefix, Node astNode) {
		this.name = prefix + astNode.getXPathNodeName();
		Iterator<Attribute> attrItr = astNode.getXPathAttributesIterator();
		if (attrItr.hasNext()) {
			attrItr.forEachRemaining(a -> attributes.add(a.getName() + ":" + a.getValue()));
		}
	}

	public String getName() {
		return this.name;
	}

	public List<String> getAttributes() {
		return this.attributes;
	}
}

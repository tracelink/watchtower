package com.tracelink.appsec.module.pmd.rules.pom;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.xml.ast.XmlNode;
import net.sourceforge.pmd.properties.PropertyDescriptor;
import net.sourceforge.pmd.properties.PropertyFactory;

/**
 * Disallow certain POM nodes directly under the project node
 * 
 * @author csmith
 *
 */
public class RestrictNodesUnderProject extends BasicPomRule {

	public static final PropertyDescriptor<List<String>> ALLOWED_SUBNODES = PropertyFactory
			.stringListProperty("subNodes").desc("Allowed nodes below the project element")
			.emptyDefaultValue().build();

	public static final PropertyDescriptor<String> ILLEGAL_TAG =
			PropertyFactory.stringProperty("illegalTag")
					.desc("Allowed nodes below the project element").defaultValue("null").build();

	private Set<String> subNodeNames = new HashSet<>();

	public RestrictNodesUnderProject() {
		definePropertyDescriptor(ALLOWED_SUBNODES);
		definePropertyDescriptor(ILLEGAL_TAG);
	}

	@Override
	protected void visitDocumentNode(XmlNode node, Document document, RuleContext ctx) {
		subNodeNames.addAll(getProperty(ALLOWED_SUBNODES));
		super.visitDocumentNode(node, document, ctx);
	}

	@Override
	protected void visitElementNode(XmlNode node, Element element, RuleContext ctx) {
		// if the parent is project node, search for allowed subnames
		if (element.getParentNode().getNodeName().equalsIgnoreCase("project")) {
			// if the subname is not in the whitelist, mark as a violation
			if (!subNodeNames.contains(element.getNodeName())) {
				setProperty(ILLEGAL_TAG, element.getNodeName());
				addViolation(ctx, node);
			}
		}
		super.visitElementNode(node, element, ctx);
	}
}

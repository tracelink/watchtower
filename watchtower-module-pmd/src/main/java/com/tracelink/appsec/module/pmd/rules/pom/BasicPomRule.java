package com.tracelink.appsec.module.pmd.rules.pom;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.jaxen.JaxenException;
import org.w3c.dom.Attr;
import org.w3c.dom.CharacterData;
import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.lang.xml.ast.XmlNode;
import net.sourceforge.pmd.lang.xml.rule.AbstractXmlRule;
import net.sourceforge.pmd.properties.PropertyDescriptor;
import net.sourceforge.pmd.properties.PropertyFactory;

/**
 * An XML rule that handles POM files. This is a separate function due to handlebars replacements
 * 
 * @author csmith
 *
 */
public class BasicPomRule extends AbstractXmlRule {

	public static final PropertyDescriptor<Boolean> RESOLVE_PROPERTIES = PropertyFactory
			.booleanProperty("resolveProperties")
			.desc("Set to attempt resolving ${property} values")
			.defaultValue(false).build();

	private static final String PROPERTIES_XPATH = "/project/properties/*";

	private static final String PROPERTY_START = "${";
	private static final String PROPERTY_END = "}";

	private Map<String, String> definedProperties = new HashMap<String, String>();

	private boolean shouldResolve = false;

	private XmlNode documentRoot;

	protected BasicPomRule() {
		definePropertyDescriptor(RESOLVE_PROPERTIES);
	}

	protected BasicPomRule(boolean shouldResolve) {
		this();
		this.shouldResolve = shouldResolve;
	}

	@Override
	protected void visit(XmlNode node, RuleContext ctx) {
		final Node domNode = node.getNode();

		// Visit the node
		visitNode(node, domNode, ctx);

		// Visit attributes
		visitAttributeNodes(node, domNode, ctx);
	}

	/**
	 * High-level node visitor, defers to sub node visitors to do work
	 * 
	 * @param node    the current XML node carried to provide global context
	 * @param domNode the current XML node as a DOM node
	 * @param ctx     the {@linkplain RuleContext}
	 */
	protected void visitNode(XmlNode node, Node domNode, RuleContext ctx) {
		switch (domNode.getNodeType()) {
			case Node.CDATA_SECTION_NODE:
				visitCDATANode(node, (CharacterData) domNode, ctx);
				break;
			case Node.COMMENT_NODE:
				visitCommentNode(node, (Comment) domNode, ctx);
				break;
			case Node.DOCUMENT_NODE:
				visitDocumentNode(node, (Document) domNode, ctx);
				break;
			case Node.ELEMENT_NODE:
				visitElementNode(node, (Element) domNode, ctx);
				break;
			case Node.TEXT_NODE:
				visitTextNode(node, (Text) domNode, ctx);
				break;
			default:
				throw new RuntimeException(
						"Unexpected node type: " + domNode.getNodeType() + " on node: " + domNode);
		}
	}

	/**
	 * Visitor for an Attributes of the node
	 * 
	 * @param node    the current XML node carried to provide global context
	 * @param domNode the current XML node as a DOM node
	 * @param ctx     the {@linkplain RuleContext}
	 */
	protected void visitAttributeNodes(XmlNode node, Node domNode, RuleContext ctx) {
		NamedNodeMap attributes = domNode.getAttributes();
		if (attributes != null) {
			for (int i = 0; i < attributes.getLength(); i++) {
				visitAttribute(node, domNode, (Attr) attributes.item(i), ctx);
			}
		}
	}

	/**
	 * Single Attribute Node visitor
	 * 
	 * @param node   the current XML node carried to provide global context
	 * @param parent the attribute's containing node
	 * @param attr   the attribute node
	 * @param ctx    the {@linkplain RuleContext}
	 */
	protected void visitAttribute(XmlNode node, Node parent, Attr attr, RuleContext ctx) {
		// leaf nodes
	}

	/**
	 * A CDATA Node visitor
	 * 
	 * @param node  the current XML node carried to provide global context
	 * @param cdata the CDATA node
	 * @param ctx   the {@linkplain RuleContext}
	 */
	protected void visitCDATANode(XmlNode node, CharacterData cdata, RuleContext ctx) {
		super.visit(node, ctx);
	}

	/**
	 * A Comment Node visitor
	 * 
	 * @param node    the current XML node carried to provide global context
	 * @param comment the comment node
	 * @param ctx     the {@linkplain RuleContext}
	 */
	protected void visitCommentNode(XmlNode node, Comment comment, RuleContext ctx) {
		super.visit(node, ctx);
	}

	/**
	 * A Document Node visitor
	 * 
	 * @param node     the current XML node carried to provide global context
	 * @param document the document node
	 * @param ctx      the {@linkplain RuleContext}
	 */
	protected void visitDocumentNode(XmlNode node, Document document, RuleContext ctx) {
		if (shouldResolve || getProperty(RESOLVE_PROPERTIES)) {
			this.documentRoot = node;
			fillProperties(node);
		}
		super.visit(node, ctx);
	}

	/**
	 * An Element Node visitor
	 * 
	 * @param node    the current XML node carried to provide global context
	 * @param element the element node
	 * @param ctx     the {@linkplain RuleContext}
	 */
	protected void visitElementNode(XmlNode node, Element element, RuleContext ctx) {
		super.visit(node, ctx);
	}

	/**
	 * A Text Node visitor
	 * 
	 * @param node the current XML node carried to provide global context
	 * @param text the text node
	 * @param ctx  the {@linkplain RuleContext}
	 */
	protected void visitTextNode(XmlNode node, Text text, RuleContext ctx) {
		super.visit(node, ctx);
	}

	/**
	 * Attempt to fill in any properties from the Pom's project into all ${} templates
	 * 
	 * @param node the current XML node carried to provide global context
	 */
	@SuppressWarnings("unchecked")
	protected void fillProperties(XmlNode node) {
		List<XmlNode> properties = null;
		try {
			properties = ((List<XmlNode>) node.findChildNodesWithXPath(PROPERTIES_XPATH)).stream()
					.filter(n -> n.getNode().getNodeType() == Node.ELEMENT_NODE)
					.collect(Collectors.toList());
		} catch (JaxenException e) {
			// xpath failed and that's weird
			e.printStackTrace();
		}
		if (properties == null) {
			return;
		}
		for (XmlNode property : properties) {
			String name = property.getNode().getNodeName().trim();
			String val = property.getNode().getFirstChild().getNodeValue();
			definedProperties.put(name, val);
		}
	}

	/**
	 * Get the value of a property by passing the property's text
	 * 
	 * @param propertyText the name of the property minus the ${ and }
	 * @return the actual value of the curly-braced property, or the property text if not found
	 */
	protected String getFromProperty(String propertyText) {
		if (propertyText == null) {
			return null;
		}
		String tempText = propertyText.trim();

		if (tempText.startsWith(PROPERTY_START) && tempText.endsWith(PROPERTY_END)) {
			tempText = tempText.substring(PROPERTY_START.length(),
					tempText.length() - PROPERTY_END.length());
			if (tempText.startsWith("project")) {
				String xpathSearch = "/" + tempText.replace('.', '/') + "/child::text";
				XmlNode node = null;
				try {
					node = (XmlNode) this.documentRoot.findChildNodesWithXPath(xpathSearch).get(0);
				} catch (JaxenException e) {
					e.printStackTrace();
				}
				if (node != null) {
					tempText = node.getNode().getNodeValue();
				}
			} else {
				tempText = definedProperties.get(tempText);
			}
		}
		return tempText;
	}

}

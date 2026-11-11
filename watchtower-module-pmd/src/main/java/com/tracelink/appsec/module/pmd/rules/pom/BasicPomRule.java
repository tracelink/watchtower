package com.tracelink.appsec.module.pmd.rules.pom;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Attr;
import org.w3c.dom.CharacterData;
import org.w3c.dom.Comment;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import net.sourceforge.pmd.lang.xml.ast.XmlNode;
import net.sourceforge.pmd.lang.xml.rule.AbstractXmlRule;
import net.sourceforge.pmd.properties.PropertyDescriptor;
import net.sourceforge.pmd.properties.PropertyFactory;
import net.sourceforge.pmd.reporting.RuleContext;

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

	/**
	 * Entry point PMD calls with the root node of the document. Unlike PMD 6's
	 * {@code AbstractXmlRule}, PMD 7's no longer recursively visits child nodes on the rule's
	 * behalf, so this rule owns the full traversal itself (see {@link #visit(XmlNode, RuleContext)}).
	 */
	@Override
	public void apply(net.sourceforge.pmd.lang.ast.Node node, RuleContext ctx) {
		visit((XmlNode) node, ctx);
	}

	/**
	 * Visits this node and then recurses into every child node. Replaces the recursive dispatch
	 * that PMD 6's {@code AbstractXmlRule.visit(XmlNode, RuleContext)} used to provide.
	 *
	 * @param node the current XML node
	 * @param ctx  the {@linkplain RuleContext}
	 */
	protected void visit(XmlNode node, RuleContext ctx) {
		final Node domNode = node.getNode();

		// Visit the node
		visitNode(node, domNode, ctx);

		// Visit attributes
		visitAttributeNodes(node, domNode, ctx);

		// Recurse into children
		for (XmlNode child : node.children()) {
			visit(child, ctx);
		}
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
		// leaf nodes; recursion into children is handled centrally by visit(XmlNode, RuleContext)
	}

	/**
	 * A Comment Node visitor
	 *
	 * @param node    the current XML node carried to provide global context
	 * @param comment the comment node
	 * @param ctx     the {@linkplain RuleContext}
	 */
	protected void visitCommentNode(XmlNode node, Comment comment, RuleContext ctx) {
		// leaf nodes; recursion into children is handled centrally by visit(XmlNode, RuleContext)
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
	}

	/**
	 * An Element Node visitor
	 *
	 * @param node    the current XML node carried to provide global context
	 * @param element the element node
	 * @param ctx     the {@linkplain RuleContext}
	 */
	protected void visitElementNode(XmlNode node, Element element, RuleContext ctx) {
		// no-op by default; subclasses override to add behavior
	}

	/**
	 * A Text Node visitor
	 *
	 * @param node the current XML node carried to provide global context
	 * @param text the text node
	 * @param ctx  the {@linkplain RuleContext}
	 */
	protected void visitTextNode(XmlNode node, Text text, RuleContext ctx) {
		// leaf nodes; recursion into children is handled centrally by visit(XmlNode, RuleContext)
	}

	/**
	 * Attempt to fill in any properties from the Pom's project into all ${} templates
	 *
	 * @param node the current XML node carried to provide global context
	 */
	protected void fillProperties(XmlNode node) {
		List<Node> properties;
		try {
			properties = findChildNodesWithXPath(node.getNode(), PROPERTIES_XPATH).stream()
					.filter(n -> n.getNodeType() == Node.ELEMENT_NODE)
					.collect(Collectors.toList());
		} catch (XPathExpressionException e) {
			// xpath failed and that's weird
			e.printStackTrace();
			return;
		}
		for (Node property : properties) {
			String name = property.getNodeName().trim();
			String val = property.getFirstChild().getNodeValue();
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
				Node node = null;
				try {
					List<Node> matches =
							findChildNodesWithXPath(this.documentRoot.getNode(), xpathSearch);
					if (!matches.isEmpty()) {
						node = matches.get(0);
					}
				} catch (XPathExpressionException e) {
					e.printStackTrace();
				}
				if (node != null) {
					tempText = node.getNodeValue();
				}
			} else {
				tempText = definedProperties.get(tempText);
			}
		}
		return tempText;
	}

	/**
	 * Evaluates an XPath expression against a DOM node, returning matching nodes.
	 *
	 * <p>
	 * Replaces PMD 6's {@code XmlNode.findChildNodesWithXPath(String)}, which used Jaxen
	 * internally and no longer exists in PMD 7 (PMD 7 moved its own rule-XPath engine to Saxon,
	 * but that internal engine isn't exposed for ad-hoc DOM queries like this). This uses the
	 * JDK's standard {@code javax.xml.xpath} (XPath 1.0) directly against the raw
	 * {@code org.w3c.dom.Node} from {@link XmlNode#getNode()} instead, avoiding any dependency on
	 * PMD's internal XPath engine.
	 *
	 * @param contextNode the DOM node to evaluate the expression against
	 * @param xpathExpr   the XPath expression
	 * @return the matching nodes, in document order
	 * @throws XPathExpressionException if the expression is invalid or evaluation fails
	 */
	private static List<Node> findChildNodesWithXPath(Node contextNode, String xpathExpr)
			throws XPathExpressionException {
		XPath xpath = XPathFactory.newInstance().newXPath();
		NodeList nodeList =
				(NodeList) xpath.evaluate(xpathExpr, contextNode, XPathConstants.NODESET);
		List<Node> results = new ArrayList<>();
		for (int i = 0; i < nodeList.getLength(); i++) {
			results.add(nodeList.item(i));
		}
		return results;
	}

}

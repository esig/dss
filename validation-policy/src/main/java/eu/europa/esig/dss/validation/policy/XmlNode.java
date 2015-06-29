/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.policy;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.lang.StringEscapeUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.XmlDom;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;

public class XmlNode {

	private String name;
	private String value;
	private String nameSpace = "";

	private HashMap<String, String> attributes = new HashMap<String, String>();

	private List<XmlNode> children = new ArrayList<XmlNode>();

	private XmlNode parentNode;

	public XmlNode(final String name) {

		this(name, null);
	}

	public XmlNode(final String name, final String value) {

		int _pos = name.indexOf(' ');
		if (_pos != -1) {

			throw new DSSException("The node name is not correct: " + name);
		}
		this.name = name;
		this.value = value;
	}

	public XmlNode(final String name, final MessageTag messageTag, final Map<String, String> attributes) {

		int _pos = name.indexOf(' ');
		if (_pos != -1) {

			throw new DSSException("The node name is not correct: " + name);
		}
		this.name = name;
		if (messageTag != null && !messageTag.equals(MessageTag.EMPTY)) {

			this.value = messageTag.getMessage();
			this.attributes.put(MessageTag.NAME_ID, messageTag.name());
		}
		if (attributes != null) {
			this.attributes.putAll(attributes);
		}
	}

	public void addChild(final XmlNode child) {

      /* if (!children.contains(child)) */
		children.add(child);
	}

	public void addChildrenOf(final XmlNode parent) {

		for (final XmlNode child : parent.children) {

			children.add(child);
		}
	}

	public void addChildren(final List<XmlDom> xmlDomList) {

		for (final XmlDom xmlDom : xmlDomList) {

			addChild(xmlDom);
		}
	}

	public void addChild(final XmlDom child) {

		final Element element = child.rootElement;
		recursiveCopy(this, element);
	}

	public void addChildrenOf(final XmlDom parent) {

		final Element element = parent.rootElement;
		final NodeList nodes = element.getChildNodes();
		for (int ii = 0; ii < nodes.getLength(); ii++) {

			final Node node = nodes.item(ii);
			if (node.getNodeType() == Node.ELEMENT_NODE) {

				recursiveCopy(this, node);
			}
		}
	}

	/**
	 * @param xmlNode the {@code XmlNode} to which the element is added
	 * @param element the {@code Node} to be copied
	 */
	private static void recursiveCopy(final XmlNode xmlNode, final Node element) {

		final String name = element.getNodeName();
		final XmlNode _xmlNode = new XmlNode(name);
		final NamedNodeMap attributes = element.getAttributes();
		for (int jj = 0; jj < attributes.getLength(); jj++) {

			final Node attrNode = attributes.item(jj);
			final String attrName = attrNode.getNodeName();
			if (!"xmlns".equals(attrName)) {

				_xmlNode.setAttribute(attrName, attrNode.getNodeValue());
			}
		}

		final NodeList nodes = element.getChildNodes();
		boolean hasElementNodes = false;
		for (int ii = 0; ii < nodes.getLength(); ii++) {

			final Node node = nodes.item(ii);
			if (node.getNodeType() == Node.ELEMENT_NODE) {

				hasElementNodes = true;
				recursiveCopy(_xmlNode, node);
			}
		}
		if (!hasElementNodes) {

			final String value = element.getTextContent();
			_xmlNode.setValue(value);
		}
		_xmlNode.setParent(xmlNode);
	}

	/**
	 * This method adds a new empty child {@code XmlNode} with the given element name.
	 *
	 * @param childName the name of the element to add
	 * @return added {@code XmlNode}
	 */
	public XmlNode addChild(final String childName) {

		final XmlNode child = new XmlNode(childName);
		children.add(child);
		child.parentNode = this;
		return child;
	}

	/**
	 * This method adds a new child {@code XmlNode} with the given element name and value.
	 *
	 * @param childName the name of the element to add
	 * @param value     the text content of the child {@code XmlNode}
	 * @return added {@code XmlNode}
	 */
	public XmlNode addChild(final String childName, final String value) {

		final XmlNode child = new XmlNode(childName, value);
		children.add(child);
		return child;
	}

	/**
	 * This method adds a new child {@code XmlNode} with the given element name. The value of the new element is set from the call to {@code messageTag.getMessage()}. A new
	 * attribute 'NAME_ID' is added with the value set to {@code messageTag.name()}.
	 *
	 * @param childName  the name of the element to add
	 * @param messageTag {@code MessageTag}
	 * @return added {@code XmlNode}
	 */
	public XmlNode addChild(final String childName, final MessageTag messageTag) {

		final XmlNode child = new XmlNode(childName, messageTag, null);
		children.add(child);
		return child;
	}

	/**
	 * This method adds a new child {@code XmlNode} with the given element name. The value of the new element is set from the call to {@code messageTag.getMessage()}. A new
	 * attribute 'NAME_ID' is added with the value set to {@code messageTag.name()}. New attributes are created from the {@code attributes} {@code Map}.
	 *
	 * @param childName  the name of the element to add
	 * @param messageTag {@code MessageTag}
	 * @param attributes {@code Map} containing pairs: attribute name, attribute value
	 * @return added {@code XmlNode}
	 */
	public XmlNode addChild(final String childName, final MessageTag messageTag, final Map<String, String> attributes) {

		final XmlNode child = new XmlNode(childName, messageTag, attributes);
		children.add(child);
		return child;
	}

	public XmlNode addFirstChild(final String childName, final String value) {

		final XmlNode child = new XmlNode(childName, value);
		children.add(0, child);
		return child;
	}

	/**
	 * This method allows to remove a first child with the given element name.
	 *
	 * @param elementName name of the element to remove
	 * @return {@code boolean} {@code true} if the child was removed, {@code false} otherwise
	 */
	public boolean removeChild(final String elementName) {

		for (final XmlNode child : children) {

			if (child.name.equals(elementName)) {

				children.remove(child);
				return true;
			}
		}
		return false;
	}

	public XmlNode getParent() {
		return parentNode;
	}

	public void setParent(final XmlNode parentNode) {

		this.parentNode = parentNode;
		if (parentNode != null) {

			parentNode.addChild(this);
		}
	}

	public String getName() {
		return name;
	}

	/**
	 * This method return the string value of the node.
	 *
	 * @return {@code String} content of the node
	 */
	public String getValue() {
		return value;
	}

	public void setValue(final String value) {
		this.value = value;
	}

	public String getNameSpace() {
		return nameSpace;
	}

	public void setNameSpace(final String nameSpace) {
		this.nameSpace = nameSpace;
	}

	/**
	 * @return the {@code Map} of associated attributes.
	 */
	public Map<String, String> getAttributes() {
		return attributes;
	}

	/**
	 * This method allows to set the attribute and its value.
	 *
	 * @param name  the attribute name
	 * @param value the attribute value
	 * @return "this" which allows to call the method again.
	 */
	public XmlNode setAttribute(final String name, final String value) {

		attributes.put(name, value);
		return this;
	}

	/**
	 * The returned list is never null.
	 *
	 * @return a modifiable list of children {@code XmlNode}.
	 */
	public List<XmlNode> getChildren() {
		return children;
	}

	private String getAttributeString() {

		final StringBuilder attributeString = new StringBuilder();
		final Set<Map.Entry<String, String>> entries = attributes.entrySet();
		for (final Entry<String, String> entry : entries) {

			String entryValue = entry.getValue();
			entryValue = StringEscapeUtils.escapeXml(entryValue);
			attributeString.append(" ").append(entry.getKey()).append("='").append(entryValue).append("'");
		}
		return attributeString.toString();
	}

	/**
	 * This method returns {@link org.w3c.dom.Document} based on the current {@link XmlNode}.
	 *
	 * @return
	 */
	public Document toDocument() {

		final InputStream inputStream = getInputStream();
		final Document document = DSSXMLUtils.buildDOM(inputStream);
		return document;
	}

	/**
	 * This method returns {@code XmlDom} representation of the current {@code XmlNode}.
	 *
	 * @return the {@code XmlDom} representation of the current {@code XmlNode}.
	 */
	public XmlDom toXmlDom() {

		final Document document = toDocument();
		final XmlDom xmlDom = new XmlDom(document);
		return xmlDom;
	}

	private void writeNodes(final XmlNode node, final StringBuilder xml, final StringBuilder indent, String nameSpace) {

		for (final XmlNode node_ : node.children) {

			xml.append(indent).append('<').append(node_.name);
			if (!node_.attributes.isEmpty()) {

				xml.append(node_.getAttributeString());
			}
			if (!node_.nameSpace.isEmpty()) {

				if (!nameSpace.equals(node_.nameSpace)) {

					xml.append(' ').append(String.format("xmlns=\"%s\"", node_.nameSpace));
					nameSpace = node_.nameSpace;
				}
			}
			xml.append('>');
			if (node_.children.size() > 0) {

				xml.append('\n');
				indent.append('\t');
				writeNodes(node_, xml, indent, nameSpace);
				indent.setLength(indent.length() - 1);
				xml.append(indent).append("</").append(node_.name).append('>').append('\n');
			} else {

				if (node_.value == null) {

					xml.append("</").append(node_.name).append('>').append('\n');
				} else {

					xml.append(node_.value).append("</").append(node_.name).append('>').append('\n');
				}
			}
		}
	}

	/**
	 * @return the {@code InputStream} representing the content of the node.
	 */
	public InputStream getInputStream() {

		try {
			final StringBuilder indent = new StringBuilder();
			final StringBuilder xml = new StringBuilder();
			final XmlNode masterNode = new XmlNode("__Master__");
			final XmlNode savedParentNode = getParent();
			if (savedParentNode != null) {

				setNameSpace(savedParentNode.getNameSpace());
			}
			setParent(masterNode);
			writeNodes(masterNode, xml, indent, "");
			parentNode = savedParentNode;
			final byte[] bytes = xml.toString().getBytes("UTF-8");
			final InputStream in = new ByteArrayInputStream(bytes);
			return in;
		} catch (UnsupportedEncodingException e) {
			throw new DSSException("Error during the conversion of the XmlNode to the InputStream :", e);
		}
	}

	@Override
	public String toString() {

		try {

			final StringBuilder indent = new StringBuilder();
			final StringBuilder xml = new StringBuilder();
			final XmlNode masterNode = new XmlNode("__Master__", null);
			final XmlNode savedParentNode = getParent();
			setParent(masterNode);
			writeNodes(masterNode, xml, indent, "");
			parentNode = savedParentNode;
			return xml.toString();
		} catch (Exception e) {

			return super.toString();
		}
	}
}

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
package eu.europa.esig.dss.xades;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.xml.XMLConstants;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;

import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.utils.Utils;

/**
 * Utility class that contains some XML related method.
 *
 */
public final class DSSXMLUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSXMLUtils.class);

	public static final String ID_ATTRIBUTE_NAME = "id";

	private static final Set<String> transforms;

	private static final Set<String> canonicalizers;

	private static Schema XADES_SCHEMA = null;

	static {

		SantuarioInitializer.init();

		transforms = new HashSet<String>();
		registerDefaultTransforms();

		canonicalizers = new HashSet<String>();
		registerDefaultCanonicalizers();
	}

	/**
	 * This method registers the default transforms.
	 */
	private static void registerDefaultTransforms() {

		registerTransform(Transforms.TRANSFORM_BASE64_DECODE);
		registerTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
		registerTransform(Transforms.TRANSFORM_XPATH);
		registerTransform(Transforms.TRANSFORM_XPATH2FILTER);
		registerTransform(Transforms.TRANSFORM_XPOINTER);
		registerTransform(Transforms.TRANSFORM_XSLT);
	}

	/**
	 * This method registers the default canonicalizers.
	 */
	private static void registerDefaultCanonicalizers() {

		registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_OMIT_COMMENTS);
		registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		registerCanonicalizer(Canonicalizer.ALGO_ID_C14N11_OMIT_COMMENTS);
		registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_PHYSICAL);
		registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_WITH_COMMENTS);
		registerCanonicalizer(Canonicalizer.ALGO_ID_C14N_EXCL_WITH_COMMENTS);
		registerCanonicalizer(Canonicalizer.ALGO_ID_C14N11_WITH_COMMENTS);
	}

	/**
	 * This class is an utility class and cannot be instantiated.
	 */
	private DSSXMLUtils() {
	}

	/**
	 * This method allows to register a transformation.
	 *
	 * @param transformURI
	 *            the URI of transform
	 * @return true if this set did not already contain the specified element
	 */
	public static boolean registerTransform(final String transformURI) {
		final boolean added = transforms.add(transformURI);
		return added;
	}

	/**
	 * This method allows to register a canonicalizer.
	 *
	 * @param c14nAlgorithmURI
	 *            the URI of canonicalization algorithm
	 * @return true if this set did not already contain the specified element
	 */
	public static boolean registerCanonicalizer(final String c14nAlgorithmURI) {
		final boolean added = canonicalizers.add(c14nAlgorithmURI);
		return added;
	}
	
	/**
	 * Indents the given node and replaces it with a new one on the document
	 * @param document {@link Document} to indent the node in
	 * @param node {@link Node} to be indented
	 * @return the indented {@link Node}
	 */
	public static Node indentAndReplace(final Document document, Node node) {
		Node indentedNode = getIndentedNode(document, node);
		Node importedNode = document.importNode(indentedNode, true);
		node.getParentNode().replaceChild(importedNode, node);
		return importedNode;
	}
	
	/**
	 * Extends the given oldNode by appending new indented childs from the given newNode
	 * @param document owner {@link Document} of the node
	 * @param newNode new {@link Node} to indent
	 * @param oldNode old {@link Node} to extend with new indented elements
	 * @return the extended {@link Node}
	 */
	public static Node indentAndExtend(final Document document, Node newNode, Node oldNode) {
		Node indentedNode = getIndentedNode(document, newNode);
		indentedNode = alignChildrenIndents(indentedNode);
		Node importedNode = document.importNode(indentedNode, true);
		NodeList nodeList = importedNode.getChildNodes();
		for (int i = getPositionToStartExtention(oldNode, importedNode); i < nodeList.getLength(); i++) {
			Node nodeToAppend = nodeList.item(i).cloneNode(true);
			if (Node.ELEMENT_NODE != nodeToAppend.getNodeType() || !checkIfExists(oldNode, nodeToAppend)) {
				oldNode.appendChild(nodeToAppend);
			}
		}
		newNode.getParentNode().replaceChild(oldNode, newNode);
		return oldNode;
	}
	
	private static int getPositionToStartExtention(Node oldNode, Node indentedNode) {
		NodeList nodeList = oldNode.getChildNodes();
		int startPosition = nodeList.getLength();
		Node child = null;
		while(oldNode.hasChildNodes()) {
			child = oldNode.getLastChild();
			if (Node.TEXT_NODE == child.getNodeType()) {
				oldNode.removeChild(child);
			} else {
				break;
			}
		}
		Integer position = getPosition(indentedNode, child);
		if (position != null) {
			return position;
		}
		return startPosition;
	}
	
	private static boolean checkIfExists(Node parentNode, Node childToCheck) {
		return getPosition(parentNode, childToCheck) != null;
	}
	
	private static Integer getPosition(Node parentNode, Node childToCheck) {
		if (parentNode != null && childToCheck != null) {
			String nodeName = childToCheck.getLocalName();
			NodeList newNodeChildList = parentNode.getChildNodes();
			for (int i = 0; i < newNodeChildList.getLength(); i++) {
				Node newChildNode = newNodeChildList.item(i);
				if (nodeName.equals(newChildNode.getLocalName())) {
					String idIdentifier = getIDIdentifier(childToCheck);
					if (idIdentifier == null || idIdentifier.equals(getIDIdentifier(newChildNode))) {
						return i + 1;
					}
				}
			}
		}
		return null;
	}
	
	/**
	 * Returns first {@link Element} child from the given parentNode
	 * @param parentNode {@link Node} to get first {@link Element} child from
	 * @return {@link Element} child
	 */
	public static Element getFirstElementChildNode(Node parentNode) {
		if (parentNode.hasChildNodes()) {
			NodeList nodeList = parentNode.getChildNodes();
			for (int i = 0; i < nodeList.getLength(); i++) {
				Node child = nodeList.item(i);
				if (Node.ELEMENT_NODE == child.getNodeType()) {
					return (Element) child;
				}
			}
		}
		return null;
	}
	
	public static Document getDocWithIndentedSignatures(final Document documentDom, String signatureId, List<String> noIndentObjectIds) {
		NodeList signatures = DomUtils.getNodeList(documentDom, "//" + XPathQueryHolder.ELEMENT_SIGNATURE);
		for (int i = 0; i < signatures.getLength(); i++) {
			Element signature = (Element) signatures.item(i);
			if (getIDIdentifier(signature).contains(signatureId)) {
				Node unsignedSignatureProperties = DomUtils.getNode(signature, ".//" + "xades:UnsignedSignatureProperties");
				Node indentedSignature = getIndentedSignature(signature, noIndentObjectIds);
				Node importedSignature = documentDom.importNode(indentedSignature, true);
				signature.getParentNode().replaceChild(importedSignature, signature);
				if (unsignedSignatureProperties != null) {
					Node newUnsignedSignatureProperties = DomUtils.getNode(signature, ".//" + "xades:UnsignedSignatureProperties");
					newUnsignedSignatureProperties.getParentNode().replaceChild(unsignedSignatureProperties, newUnsignedSignatureProperties);
				}
			}
		}
		return documentDom;
	}
	
	private static Node getIndentedSignature(final Node signature, List<String> noIndentObjectIds) {
		Node indentedSignature = getIndentedNode(signature);
		NodeList sigChildNodes = signature.getChildNodes();
		for (int i = 0; i < sigChildNodes.getLength(); i++) {
			Node childNode = sigChildNodes.item(i);
			if (childNode.getNodeType() == Node.ELEMENT_NODE) {
				Element sigChild = (Element) childNode;
				String idAttribute = getIDIdentifier(sigChild);
				if (noIndentObjectIds.contains(idAttribute)) {
					Node nodeToReplace = DomUtils.getNode(indentedSignature, "//*" + DomUtils.getXPathByIdAttribute(idAttribute));
					Node importedNode = indentedSignature.getOwnerDocument().importNode(sigChild, true);
					indentedSignature.replaceChild(importedNode, nodeToReplace);
				}
			}
		}
		return indentedSignature;
	}
	
	/**
	 * Returns an indented xmlNode
	 * @param documentDom is an owner {@link Document} of the xmlNode
	 * @param xmlNode {@link Node} to indent
	 * @return an indented {@link Node} xmlNode
	 */
	public static Node getIndentedNode(final Node documentDom, final Node xmlNode) {
		NodeList signatures = DomUtils.getNodeList(documentDom, "//" + XPathQueryHolder.ELEMENT_SIGNATURE);
		for (int i = 0; i < signatures.getLength(); i++) {
			Node signature = signatures.item(i);
			NodeList candidateList;
			String idAttribute = getIDIdentifier(xmlNode);
			if (idAttribute != null) {
				candidateList = DomUtils.getNodeList(signature, ".//*" + DomUtils.getXPathByIdAttribute(idAttribute));
			} else {
				candidateList = DomUtils.getNodeList(signature, ".//" +  xmlNode.getNodeName());
			}
			if (isNodeListContains(candidateList, xmlNode)) {
				Node indentedSignature = getIndentedNode(signature);
				Node indentedXmlNode;
				if (idAttribute != null) {
					indentedXmlNode = DomUtils.getNode(indentedSignature, ".//*" + DomUtils.getXPathByIdAttribute(idAttribute));
				} else {
					indentedXmlNode = DomUtils.getNode(indentedSignature, ".//" +  xmlNode.getNodeName());
				}
				if (indentedXmlNode != null) {
					return indentedXmlNode;
				}
			}
		}
		return xmlNode;
	}
	
	private static Node getIndentedNode(final Node xmlNode) {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
			Transformer transformer = DomUtils.getPrettyPrintTransformer();
			Source source = new DOMSource(xmlNode);
			StreamResult result = new StreamResult(bos);
			transformer.transform(source, result);
			byte[] bytes = bos.toByteArray();
			return DomUtils.buildDOM(bytes).getFirstChild();
		} catch (Exception e) {
			throw new DSSException("Cannot pretty print the node", e);
		}
	}
	
	private static boolean isNodeListContains(final NodeList nodeList, final Node node) {
		for (int i = 0; i < nodeList.getLength(); i++) {
			Node child = nodeList.item(i);
			if (child == node) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Aligns indents for all children of the given node
	 * @param parentNode {@link Node} to align children into
	 * @return the given {@link Node} with aligned children
	 */
	public static Node alignChildrenIndents(Node parentNode) {
		if (parentNode.hasChildNodes()) {
			NodeList nodeChildren = parentNode.getChildNodes();
			String targetIndent = getTargetIndent(nodeChildren);
			if (targetIndent != null) {
				for (int i = 0; i < nodeChildren.getLength() - 1; i++) {
					Node node = nodeChildren.item(i);
					if (Node.TEXT_NODE == node.getNodeType()) {
						node.setNodeValue(targetIndent);
					}
				}
				Node lastChild = parentNode.getLastChild();
				targetIndent = targetIndent.substring(0, targetIndent.length() - DomUtils.TRANSFORMER_INDENT_NUMBER);
				switch (lastChild.getNodeType()) {
					case Node.ELEMENT_NODE:
						DomUtils.setTextNode(parentNode.getOwnerDocument(), (Element)parentNode, targetIndent);
						break;
					case Node.TEXT_NODE:
						lastChild.setNodeValue(targetIndent);
					default:
						break;
				}
			}
		}
		return parentNode;
	}
	
	private static String getTargetIndent(NodeList nodeChildren) {
		for (int i = 0; i < nodeChildren.getLength() - 1; i++) {
			Node node = nodeChildren.item(i);
			if (Node.TEXT_NODE == node.getNodeType()) {
				return node.getNodeValue();
			}
		}
		return null;
	}

	/**
	 * This method performs the serialization of the given node
	 *
	 * @param xmlNode
	 *            The node to be serialized.
	 * @return the serialized bytes
	 */
	public static byte[] serializeNode(final Node xmlNode) {
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
			Transformer transformer = DomUtils.getSecureTransformer();
			Document document = null;
			if (Node.DOCUMENT_NODE == xmlNode.getNodeType()) {
				document = (Document) xmlNode;
			} else {
				document = xmlNode.getOwnerDocument();
			}

			if (document != null) {
				String xmlEncoding = document.getXmlEncoding();
				if (Utils.isStringNotBlank(xmlEncoding)) {
					transformer.setOutputProperty(OutputKeys.ENCODING, xmlEncoding);
				}
			}

			StreamResult result = new StreamResult(bos);
			Source source = new DOMSource(xmlNode);
			transformer.transform(source, result);
			
			return bos.toByteArray();
		} catch (Exception e) {
			throw new DSSException("An error occurred during a node serialization.", e);
		}
	}

	/**
	 * This method says if the framework can canonicalize an XML data with the provided method.
	 *
	 * @param canonicalizationMethod
	 *            the canonicalization method to be checked
	 * @return true if it is possible to canonicalize false otherwise
	 */
	public static boolean canCanonicalize(final String canonicalizationMethod) {
		return canonicalizers.contains(canonicalizationMethod);
	}

	/**
	 * This method canonicalizes the given array of bytes using the {@code canonicalizationMethod} parameter.
	 *
	 * @param canonicalizationMethod
	 *            canonicalization method
	 * @param toCanonicalizeBytes
	 *            array of bytes to canonicalize
	 * @return array of canonicalized bytes
	 * @throws DSSException
	 *             if any error is encountered
	 */
	public static byte[] canonicalize(final String canonicalizationMethod, final byte[] toCanonicalizeBytes) throws DSSException {
		try {
			final Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
			return c14n.canonicalize(toCanonicalizeBytes);
		} catch (Exception e) {
			throw new DSSException("Cannot canonicalize the binaries", e);
		}
	}

	/**
	 * This method canonicalizes the given {@code Node}.
	 *
	 * @param canonicalizationMethod
	 *            canonicalization method
	 * @param node
	 *            {@code Node} to canonicalize
	 * @return array of canonicalized bytes
	 */
	public static byte[] canonicalizeSubtree(final String canonicalizationMethod, final Node node) {
		try {
			final Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
			return c14n.canonicalizeSubtree(node);
		} catch (Exception e) {
			throw new DSSException("Cannot canonicalize the subtree", e);
		}
	}

	/**
	 * This methods canonicalizes or serializes the given node depending on the canonicalization method (can be null)
	 * 
	 * @param canonicalizationMethod
	 *            the canonicalization method or null
	 * @param node
	 *            the node to be canonicalized/serialized
	 * @return array of bytes
	 */
	public static byte[] canonicalizeOrSerializeSubtree(final String canonicalizationMethod, final Node node) {
		if (canonicalizationMethod == null) {
			return serializeNode(node);
		} else {
			return canonicalizeSubtree(canonicalizationMethod, node);
		}
	}

	/**
	 * An ID attribute can only be dereferenced if it is declared in the validation context. This behaviour is caused by
	 * the fact that the attribute does not have attached type of information. Another solution is to parse the XML
	 * against some DTD or XML schema. This process adds the necessary type of information to each ID attribute.
	 *
	 * @param element
	 */
	public static void recursiveIdBrowse(final Element element) {

		for (int ii = 0; ii < element.getChildNodes().getLength(); ii++) {

			final Node node = element.getChildNodes().item(ii);
			if (node.getNodeType() == Node.ELEMENT_NODE) {

				final Element childElement = (Element) node;
				setIDIdentifier(childElement);
				recursiveIdBrowse(childElement);
			}
		}
	}

	/**
	 * If this method finds an attribute with names ID (case-insensitive) then it is
	 * returned. If there is more than one ID attributes then the first one is
	 * returned.
	 *
	 * @param node
	 *             the node to be checked
	 * @return the ID attribute value or null
	 */
	public static String getIDIdentifier(final Node node) {
		final NamedNodeMap attributes = node.getAttributes();
		for (int jj = 0; jj < attributes.getLength(); jj++) {
			final Node item = attributes.item(jj);
			final String localName = item.getLocalName() != null ? item.getLocalName() : item.getNodeName();
			if (localName != null) {
				if (Utils.areStringsEqualIgnoreCase(ID_ATTRIBUTE_NAME, localName)) {
					return item.getTextContent();
				}
			}
		}
		return null;
	}

	/**
	 * If this method finds an attribute with names ID (case-insensitive) then declares it to be a user-determined ID
	 * attribute.
	 *
	 * @param childElement
	 */
	public static void setIDIdentifier(final Element childElement) {

		final NamedNodeMap attributes = childElement.getAttributes();
		for (int jj = 0; jj < attributes.getLength(); jj++) {

			final Node item = attributes.item(jj);
			final String localName = item.getLocalName();
			final String nodeName = item.getNodeName();
			if (localName != null) {
				if (Utils.areStringsEqualIgnoreCase(ID_ATTRIBUTE_NAME, localName)) {
					childElement.setIdAttribute(nodeName, true);
					break;
				}
			}
		}
	}

	private static Schema getXAdESValidationSchema() {
		if (XADES_SCHEMA == null) {
			try (InputStream xsd1 = DSSXMLUtils.class.getResourceAsStream("/XAdES01903v132-201601.xsd");
					InputStream xsd2 = DSSXMLUtils.class.getResourceAsStream("/XAdES01903v141-201601.xsd")) {
				SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
				XADES_SCHEMA = sf.newSchema(new Source[] { new StreamSource(xsd1), new StreamSource(xsd2) });
			} catch (Exception e) {
				throw new DSSException("Unable to load the XSD files", e);
			}
		}
		return XADES_SCHEMA;
	}

	/**
	 * This method allows to validate a DSSDocument XML against the XAdES XSD schema.
	 *
	 * @param document
	 *            {@code DSSDocument} document to validate
	 * @throws SAXException
	 *             if the document content is not valid
	 */
	public static void validateAgainstXSD(DSSDocument document) throws SAXException {
		try (InputStream is = document.openStream()) {
			final Validator validator = getXAdESValidationSchema().newValidator();
			validator.validate(new StreamSource(is));
		} catch (IOException e) {
			throw new DSSException("Unable to read document", e);
		}
	}

	/**
	 * This method allows to validate an XML against the XAdES XSD schema.
	 *
	 * @param streamSource
	 *            {@code InputStream} XML to validate
	 * @return null if the XSD validates the XML, error message otherwise
	 */
	public static String validateAgainstXSD(final StreamSource streamSource) {
		try {
			final Validator validator = getXAdESValidationSchema().newValidator();
			validator.validate(streamSource);
			return Utils.EMPTY_STRING;
		} catch (Exception e) {
			LOG.warn("Error during the XML schema validation!", e);
			return e.getMessage();
		}
	}

	public static boolean isOid(String policyId) {
		return policyId != null && policyId.matches("^(?i)urn:oid:.*$");
	}
	
	/**
	 * Keeps only code of the oid string
	 * e.g. "urn:oid:1.2.3" to "1.2.3"
	 * @param oid {@link String} Oid
	 * @return Oid Code
	 */
	public static String getOidCode(String oid) {
		return oid.substring(oid.lastIndexOf(':') + 1);
	}

	/**
	 * This method is used to detect duplicate id values
	 * 
	 * @param doc
	 *            the document to be analyzed
	 * @return TRUE if a duplicate id is detected
	 */
	public static boolean isDuplicateIdsDetected(DSSDocument doc) {
		try {
			Document dom = DomUtils.buildDOM(doc);
			Element root = dom.getDocumentElement();
			recursiveIdBrowse(root);
			XPathExpression xPathExpression = DomUtils.createXPathExpression("//*/@*");
			NodeList nodeList = (NodeList) xPathExpression.evaluate(root, XPathConstants.NODESET);
			for (int i = 0; i < nodeList.getLength(); i++) {
				Attr attr = (Attr) nodeList.item(i);
				if (Utils.areStringsEqualIgnoreCase(ID_ATTRIBUTE_NAME, attr.getName())) {
					XPathExpression xpathAllById = DomUtils.createXPathExpression("//*[@" + attr.getName() + "='" + attr.getValue() + "']");
					NodeList nodeListById = (NodeList) xpathAllById.evaluate(root, XPathConstants.NODESET);
					if (nodeListById.getLength() != 1) {
						LOG.warn("Problem detected with Id '{}', nb occurences = {}", attr.getValue(), nodeListById.getLength());
						return true;
					}
				}
			}
		} catch (XPathExpressionException e) {
			throw new DSSException("Unable to check if duplicate ids are present", e);
		}
		return false;
	}

}

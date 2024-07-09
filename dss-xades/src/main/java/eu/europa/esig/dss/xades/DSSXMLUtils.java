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

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.jaxb.common.XSDAbstractUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.Digest;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.xades.reference.DSSReference;
import eu.europa.esig.dss.xades.reference.DSSTransform;
import eu.europa.esig.dss.xades.reference.DSSTransformOutput;
import eu.europa.esig.dss.xades.reference.ReferenceOutputType;
import eu.europa.esig.dss.xades.signature.PrettyPrintTransformer;
import eu.europa.esig.dss.xades.validation.DSSDocumentXMLSignatureInput;
import eu.europa.esig.dss.xades.validation.DetachedSignatureResolver;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
import eu.europa.esig.dss.xml.common.definition.AbstractPath;
import eu.europa.esig.dss.xml.common.definition.DSSElement;
import eu.europa.esig.dss.xml.common.definition.DSSNamespace;
import eu.europa.esig.dss.xml.utils.DomUtils;
import eu.europa.esig.dss.xml.utils.SantuarioInitializer;
import eu.europa.esig.dss.xades.definition.XAdESNamespace;
import eu.europa.esig.dss.xades.definition.XAdESPath;
import eu.europa.esig.dss.xades.definition.xades111.XAdES111Path;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Element;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Path;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigAttribute;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigElement;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigNamespace;
import eu.europa.esig.dss.xml.common.definition.xmldsig.XMLDSigPath;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.Manifest;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.ReferenceNotInitializedException;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import javax.xml.transform.Source;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Utility class that contains some XML related method.
 *
 */
public final class DSSXMLUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSXMLUtils.class);

	/** List of supported transforms */
	private static final Set<String> transforms;

	/** List of transforms resulting to a NodeSet output */
	private static final Set<String> transformsWithNodeSetOutput;

	/** Value used to pretty print xades signature */
	public static final int TRANSFORMER_INDENT_NUMBER = 4;

	/** The Enveloped-signature transformation */
	private static final String TRANSFORMATION_EXCLUDE_SIGNATURE = "not(ancestor-or-self::ds:Signature)";

	/** The XPath transform name */
	private static final String TRANSFORMATION_XPATH_NODE_NAME = "XPath";

	/** The SPDocDigestAsInSpecification transform algorithm URI for a custom SignaturePolicy processing */
	public static final String SP_DOC_DIGEST_AS_IN_SPECIFICATION_ALGORITHM_URI =
			"http://uri.etsi.org/01903/v1.3.2/SignaturePolicy/SPDocDigestAsInSpecification";

	/** SAML namespace definition */
	public static final DSSNamespace SAML_NAMESPACE = new DSSNamespace("urn:oasis:names:tc:SAML:2.0:assertion", "saml2");

	static {
		SantuarioInitializer.init();

		transforms = new HashSet<>();
		registerDefaultTransforms();
		
		transformsWithNodeSetOutput = new HashSet<>();
		registerTransformsWithNodeSetOutput();

		registerXAdESNamespaces();
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
	 * This method registers transforms resulting to a node-set according to XMLDSIG
	 */
	private static void registerTransformsWithNodeSetOutput() {
		registerTransformWithNodeSetOutput(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
		registerTransformWithNodeSetOutput(Transforms.TRANSFORM_XPATH);
		registerTransformWithNodeSetOutput(Transforms.TRANSFORM_XPATH2FILTER);
	}

	/**
	 * Registers the XAdES namespaces
	 */
	public static void registerXAdESNamespaces() {
		DomUtils.registerNamespace(XMLDSigNamespace.NS);

		DomUtils.registerNamespace(XAdESNamespace.XADES_111);
		DomUtils.registerNamespace(XAdESNamespace.XADES_122);
		DomUtils.registerNamespace(XAdESNamespace.XADES_132);
		DomUtils.registerNamespace(XAdESNamespace.XADES_141);
		// DO NOT register "xades"

		DomUtils.registerNamespace(SAML_NAMESPACE);
	}

	/**
	 * This class is a utility class and cannot be instantiated.
	 */
	private DSSXMLUtils() {
		// empty
	}

	/**
	 * This method allows to register a transformation.
	 *
	 * @param transformURI
	 *            the URI of transform
	 * @return true if this set did not already contain the specified element
	 */
	public static boolean registerTransform(final String transformURI) {
		return transforms.add(transformURI);
	}

	/**
	 * This method allows to register a transformation resulting to a node-set output.
	 * See XMLDSIG for more information
	 *
	 * @param transformURI
	 *            the URI of transform
	 * @return true if this set did not already contain the specified element
	 */
	public static boolean registerTransformWithNodeSetOutput(final String transformURI) {
		return transformsWithNodeSetOutput.add(transformURI);
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
		for (int i = getPositionToStartExtension(oldNode, importedNode); i < nodeList.getLength(); i++) {
			Node nodeToAppend = nodeList.item(i).cloneNode(true);
			if (Node.ELEMENT_NODE != nodeToAppend.getNodeType() || !checkIfExists(oldNode, nodeToAppend)) {
				oldNode.appendChild(nodeToAppend);
			}
		}
		newNode.getParentNode().replaceChild(oldNode, newNode);
		return oldNode;
	}
	
	private static int getPositionToStartExtension(Node oldNode, Node indentedNode) {
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
	 * Pretty prints a signature in the given document
	 *
	 * @param documentDom {@link Document} to pretty print
	 * @param signatureId {@link String} id of a ds:Signature element to be pretty-printed
	 * @param noIndentObjectIds {@link String} id of elements to not pretty-print
	 * @return {@link Document} with a pretty-printed signature
	 */
	public static Document getDocWithIndentedSignature(final Document documentDom, String signatureId,
													   List<String> noIndentObjectIds) {
		NodeList signatures = DomUtils.getNodeList(documentDom, XMLDSigPath.ALL_SIGNATURES_PATH);
		for (int i = 0; i < signatures.getLength(); i++) {
			Element signature = (Element) signatures.item(i);
			String signatureAttrIdValue = getIDIdentifier(signature);
			if (Utils.isStringNotEmpty(signatureAttrIdValue) && signatureAttrIdValue.contains(signatureId)) {
				Node unsignedSignatureProperties = DomUtils.getNode(signature,
						AbstractPath.allFromCurrentPosition(XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES));
				Node indentedSignature = getIndentedSignature(signature, noIndentObjectIds);
				Node importedSignature = documentDom.importNode(indentedSignature, true);
				signature.getParentNode().replaceChild(importedSignature, signature);
				if (unsignedSignatureProperties != null) {
					Node newUnsignedSignatureProperties = DomUtils.getNode(signature,
							AbstractPath.allFromCurrentPosition(XAdES132Element.UNSIGNED_SIGNATURE_PROPERTIES));
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
					Node nodeToReplace = DomUtils.getElementById(indentedSignature, idAttribute);
					Node importedNode = indentedSignature.getOwnerDocument().importNode(sigChild, true);
					indentedSignature.replaceChild(importedNode, nodeToReplace);
				}
			}
		}
		return indentedSignature;
	}
	
	/**
	 * Returns an indented xmlNode
	 *
	 * @param documentDom is an owner {@link Document} of the xmlNode
	 * @param xmlNode {@link Node} to indent
	 * @return an indented {@link Node} xmlNode
	 */
	public static Node getIndentedNode(final Node documentDom, final Node xmlNode) {
		NodeList signatures = DomUtils.getNodeList(documentDom, XMLDSigPath.ALL_SIGNATURES_PATH);

		String pathAllFromCurrentPosition;
		// TODO handle by namespace
		DSSElement element = XAdES132Element.fromTagName(xmlNode.getLocalName());
		if (element != null) {
			pathAllFromCurrentPosition = AbstractPath.allFromCurrentPosition(element);
		} else {
			pathAllFromCurrentPosition = ".//" + xmlNode.getNodeName();
		}

		for (int i = 0; i < signatures.getLength(); i++) {
			Node signature = signatures.item(i);
			NodeList candidateList;
			String idAttribute = getIDIdentifier(xmlNode);
			if (idAttribute != null) {
				candidateList = DomUtils.getNodeList(signature, ".//*" + DomUtils.getXPathByIdAttribute(idAttribute));
			} else {
				candidateList = DomUtils.getNodeList(signature, pathAllFromCurrentPosition);
			}
			if (isNodeListContains(candidateList, xmlNode)) {
				Node indentedSignature = getIndentedNode(signature);
				Node indentedXmlNode;
				if (idAttribute != null) {
					indentedXmlNode = DomUtils.getElementById(indentedSignature, idAttribute);
				} else {
					NodeList indentedXmlNodes = DomUtils.getNodeList(indentedSignature, pathAllFromCurrentPosition);
					if (indentedXmlNodes.getLength() == 0) {
						throw new IllegalStateException(String.format("No elements found matching the '%s' XPath expression!", pathAllFromCurrentPosition));
					}
					// return the last item
					indentedXmlNode = indentedXmlNodes.item(indentedXmlNodes.getLength() - 1);
				}
				if (indentedXmlNode != null) {
					return indentedXmlNode;
				}
			}
		}
		return xmlNode;
	}
	
	private static Node getIndentedNode(final Node xmlNode) {
		PrettyPrintTransformer prettyPrintTransformer = new PrettyPrintTransformer();
		return prettyPrintTransformer.transform(xmlNode);
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
	 *
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
				targetIndent = targetIndent.substring(0, targetIndent.length() - TRANSFORMER_INDENT_NUMBER);
				switch (lastChild.getNodeType()) {
				case Node.ELEMENT_NODE:
					DomUtils.setTextNode(parentNode.getOwnerDocument(), (Element) parentNode, targetIndent);
					break;
				case Node.TEXT_NODE:
					lastChild.setNodeValue(targetIndent);
					break;
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
	 * An ID attribute can only be dereferenced if it is declared in the validation context. This behaviour is caused by
	 * the fact that the attribute does not have attached type of information. Another solution is to parse the XML
	 * against some DTD or XML schema. This process adds the necessary type of information to each ID attribute.
	 *
	 * @param element {@link Element}
	 */
	public static void recursiveIdBrowse(final Element element) {
		setIDIdentifier(element);
		for (int ii = 0; ii < element.getChildNodes().getLength(); ii++) {
			final Node node = element.getChildNodes().item(ii);
			if (node.getNodeType() == Node.ELEMENT_NODE) {
				recursiveIdBrowse((Element) node);
			}
		}
	}

	/**
	 * If this method finds an attribute with the name ID (case-insensitive) then it is
	 * returned. If there is more than one ID attributes then the first one is
	 * returned.
	 *
	 * @param node
	 *             the node to be checked
	 * @return the ID attribute value or null
	 */
	public static String getIDIdentifier(final Node node) {
		return getAttribute(node, XMLDSigAttribute.ID.getAttributeName());
	}
	
	/**
	 * Returns attribute value for the given attribute name if exist, otherwise returns NULL
	 * @param node {@link Node} to get attribute value from
	 * @param attributeName {@link String} name of the attribute to get value for
	 * @return {@link String} value of the attribute
	 */
	public static String getAttribute(final Node node, final String attributeName) {
		final NamedNodeMap attributes = node.getAttributes();
		for (int jj = 0; jj < attributes.getLength(); jj++) {
			final Node item = attributes.item(jj);
			final String localName = item.getLocalName() != null ? item.getLocalName() : item.getNodeName();
			if (Utils.areStringsEqualIgnoreCase(attributeName, localName)) {
				return item.getTextContent();
			}
		}
		return null;
	}

	/**
	 * If this method finds an attribute with names ID (case-insensitive) then declares it to be a user-determined ID
	 * attribute.
	 *
	 * @param childElement {@link Element}
	 */
	public static void setIDIdentifier(final Element childElement) {

		final NamedNodeMap attributes = childElement.getAttributes();
		for (int jj = 0; jj < attributes.getLength(); jj++) {

			final Node item = attributes.item(jj);
			final String localName = item.getLocalName();
			final String nodeName = item.getNodeName();
			if (localName != null && Utils.areStringsEqualIgnoreCase(XMLDSigAttribute.ID.getAttributeName(), localName)) {
				childElement.setIdAttribute(nodeName, true);
				break;
			}
		}
	}

	/**
	 * This method allows to validate an XML against the XAdES XSD schema.
	 *
	 * @param xsdUtils the XSD Utils class to be used
	 * @param source   {@code Source} XML to validate
	 * @return an empty list if the XSD validates the XML, error messages otherwise
	 */
	public static List<String> validateAgainstXSD(XSDAbstractUtils xsdUtils, final Source source) {
		return xsdUtils.validateAgainstXSD(source);
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
				if (Utils.areStringsEqualIgnoreCase(XMLDSigAttribute.ID.getAttributeName(), attr.getName())) {
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
	
	/**
	 * Returns bytes of the original referenced data
	 * @param reference {@link Reference} to get bytes from
	 * @return byte array containing original data
	 */
	public static byte[] getReferenceOriginalContentBytes(Reference reference) {
		
		try {
			// returns bytes after transformation in case of enveloped signature
			Transforms transforms = reference.getTransforms();
			if (transforms != null) {
				Element transformsElement = transforms.getElement();
				NodeList transformChildNodes = transformsElement.getChildNodes();
				if (transformChildNodes != null && transformChildNodes.getLength() > 0) {
					for (int i = 0; i < transformChildNodes.getLength(); i++) {
						Node transformation = transformChildNodes.item(i);
						if (isEnvelopedTransform(transformation)) {
							return reference.getReferencedBytes();
						}
					    // if enveloped transformations are not applied to the signature go further and 
						// return bytes before transformation
					}
				}
			}
			
		} catch (XMLSecurityException e) {
			// if exception occurs during the transformations
			LOG.warn("Signature reference with id [{}] is corrupted or has an invalid format. "
					+ "Original data cannot be obtained. Reason: [{}]", reference.getId(), e.getMessage());
			
		}
		// otherwise bytes before transformation
		return getBytesBeforeTransformation(reference);
	}
	
	private static boolean isEnvelopedTransform(Node transformation) {
		final String algorithm = DomUtils.getValue(transformation, "@Algorithm");
		if (Transforms.TRANSFORM_ENVELOPED_SIGNATURE.equals(algorithm)) {
			return true;
		} else if (Transforms.TRANSFORM_XPATH.equals(algorithm) || 
				Transforms.TRANSFORM_XPATH2FILTER.equals(algorithm)) {
			NodeList childNodes = transformation.getChildNodes();
			for (int j = 0; j < childNodes.getLength(); j++) {
				Node item = childNodes.item(j);
				if (Node.ELEMENT_NODE == item.getNodeType() && TRANSFORMATION_XPATH_NODE_NAME.equals(item.getLocalName()) &&
						TRANSFORMATION_EXCLUDE_SIGNATURE.equals(item.getTextContent())) {
					return true;
				}
			}
		}
		return false;
	}
	
	private static byte[] getBytesBeforeTransformation(Reference reference) {
		try {
			return reference.getContentsBeforeTransformation().getBytes();
		} catch (ReferenceNotInitializedException e) {
			// if exception occurs during an attempt to access reference original data
			LOG.warn("Original data is not provided for the reference with id [{}]. Reason: [{}]", reference.getId(), e.getMessage());
		} catch (IOException | CanonicalizationException e) {
			// if exception occurs by another reason
			LOG.warn("Unable to retrieve the content of reference with id [{}].", reference.getId(), e);
		}
		// in case of exceptions return null value
		return null;
	}

	/**
	 * This method extracts the Digest algorithm and value from an element of type
	 * DigestAlgAndValueType
	 * 
	 * @param element
	 *                an Element of type DigestAlgAndValueType
	 * @return an instance of Digest
	 */
	public static Digest getDigestAndValue(Element element) {
		if (element == null) {
			return null;
		}

		String digestAlgorithmUri;
		String digestValueBase64;
		if (XAdESNamespace.XADES_111.isSameUri(element.getNamespaceURI())) {
			digestAlgorithmUri = DomUtils.getValue(element, XAdES111Path.DIGEST_METHOD_ALGORITHM_PATH);
			digestValueBase64 = DomUtils.getValue(element, XAdES111Path.DIGEST_VALUE_PATH);
		} else {
			digestAlgorithmUri = DomUtils.getValue(element, XMLDSigPath.DIGEST_METHOD_ALGORITHM_PATH);
			digestValueBase64 = DomUtils.getValue(element, XMLDSigPath.DIGEST_VALUE_PATH);
		}

		final DigestAlgorithm digestAlgorithm = getDigestAlgorithm(digestAlgorithmUri);
		final byte[] digestValue = getDigestValue(digestValueBase64);

		if (digestAlgorithm == null || Utils.isArrayEmpty(digestValue)) {
			LOG.warn("Unable to read object DigestAlgAndValueType (XMLDSig or XAdES 1.1.1)");
			return null;

		} else {
			return new Digest(digestAlgorithm, digestValue);
		}

	}

	private static byte[] getDigestValue(String digestValueBase64) {
		byte[] result = null;
		if (Utils.isStringEmpty(digestValueBase64)) {
			LOG.warn("An empty DigestValue obtained!");

		} else if (!Utils.isBase64Encoded(digestValueBase64)) {
			LOG.warn("The DigestValue is not base64 encoded! Obtained string : {}", digestValueBase64);

		} else {
			result = Utils.fromBase64(digestValueBase64);
		}
		return result;
	}

	private static DigestAlgorithm getDigestAlgorithm(String digestAlgorithmUri) {
		DigestAlgorithm result = null;
		if (Utils.isStringNotEmpty(digestAlgorithmUri)) {
			try {
				result = DigestAlgorithm.forXML(digestAlgorithmUri);
			} catch (IllegalArgumentException e) {
				LOG.warn("Unable to retrieve the used digest algorithm", e);
			}
		}
		return result;
	}

	/**
	 * Determines if the given {@code reference} refers to SignedProperties element
	 *
	 * @param reference {@link Reference} to check
	 * @param xadesPaths {@link XAdESPath}
	 * @return TRUE if the reference refers to the SignedProperties, FALSE otherwise
	 */
	public static boolean isSignedProperties(final Reference reference, final XAdESPath xadesPaths) {
		return xadesPaths.getSignedPropertiesUri().equals(reference.getType());
	}

	/**
	 * Determines if the given {@code reference} refers to CounterSignature element
	 *
	 * @param reference {@link Reference} to check
	 * @param xadesPaths {@link XAdESPath}
	 * @return TRUE if the reference refers to the CounterSignature, FALSE otherwise
	 */
	public static boolean isCounterSignature(final Reference reference, final XAdESPath xadesPaths) {
		return xadesPaths.getCounterSignatureUri().equals(reference.getType());
	}
	
	/**
	 * Checks if the given reference is linked to a KeyInfo element
	 * 
	 * @param reference
	 *                  the {@link Reference} to check
	 * @param signature
	 *                  the {@link Element} signature the given reference belongs to
	 * @return TRUE if the reference is a KeyInfo reference, FALSE otherwise
	 */
	public static boolean isKeyInfoReference(final Reference reference, final Element signature) {
		String uri = reference.getURI();
		uri = DomUtils.getId(uri);
		Element keyInfoElement = DomUtils.getElement(signature, XMLDSigPath.KEY_INFO_PATH + DomUtils.getXPathByIdAttribute(uri));
		return keyInfoElement != null;
	}
	
	/**
	 * Checks if the given reference is linked to a SignatureProperties element or one of its SignatureProperty children
	 * 
	 * @param reference
	 *                  the {@link Reference} to check
	 * @param signature
	 *                  the {@link Element} signature the given reference belongs to
	 * @return TRUE if the reference is a SignatureProperties reference, FALSE otherwise
	 */
	public static boolean isSignaturePropertiesReference(final Reference reference, final Element signature) {
		String uri = reference.getURI();
		uri = DomUtils.getId(uri);
		Element signaturePropertiesElement = DomUtils.getElement(signature, XMLDSigPath.SIGNATURE_PROPERTIES_PATH + DomUtils.getXPathByIdAttribute(uri));
		Element signaturePropertyElement = DomUtils.getElement(signature, XMLDSigPath.SIGNATURE_PROPERTY_PATH + DomUtils.getXPathByIdAttribute(uri));
		return signaturePropertiesElement != null || signaturePropertyElement != null;
	}
	
	/**
	 * Checks if the given {@code referenceType} is an xmldsig Object type
	 * @param referenceType {@link String} to check the type for
	 * @return TRUE if the provided {@code referenceType} is an Object type, FALSE otherwise
	 */
	public static boolean isObjectReferenceType(String referenceType) {
		return XMLDSigPath.OBJECT_TYPE.equals(referenceType);
	}
	
	/**
	 * Checks if the given {@code referenceType} is an xmldsig Manifest type
	 * @param referenceType {@link String} to check the type for
	 * @return TRUE if the provided {@code referenceType} is a Manifest type, FALSE otherwise
	 */
	public static boolean isManifestReferenceType(String referenceType) {
		return XMLDSigPath.MANIFEST_TYPE.equals(referenceType);
	}
	
	/**
	 * Checks if the given {@code referenceType} is an etsi Countersignature type
	 * @param referenceType {@link String} to check the type for
	 * @return TRUE if the provided {@code referenceType} is a Countersignature type, FALSE otherwise
	 */
	public static boolean isCounterSignatureReferenceType(String referenceType) {
		return XMLDSigPath.COUNTER_SIGNATURE_TYPE.equals(referenceType);
	}
	
	/**
	 * XMLDSIG 4.4.3.2 The Reference Processing Model
	 * 
	 * A 'same-document' reference is defined as a URI-Reference that consists of 
	 * a hash sign ('#') followed by a fragment or alternatively consists of an empty URI
	 * 
	 * @param referenceUri {@link String} uri of a reference to check
	 * @return TRUE is the URI points to a same-document, FALSE otherwise
	 */
	public static boolean isSameDocumentReference(String referenceUri) {
		return Utils.EMPTY_STRING.equals(referenceUri) || DomUtils.startsFromHash(referenceUri);
	}

	/**
	 * Gets ds:Object by its Id from the ds:Signature element
	 *
	 * @param signatureElement {@link Element} the signature element to extract the signed ds:Object from
	 * @param id {@link String} object Id
	 * @return {@link Element} Object element
	 */
	public static Element getObjectById(Element signatureElement, String id) {
		if (Utils.isStringNotBlank(id)) {
			try {
				String objectById = XMLDSigPath.OBJECT_PATH + DomUtils.getXPathByIdAttribute(id);
				return DomUtils.getElement(signatureElement, objectById);
			} catch (Exception e) {
				String errorMessage = "An error occurred on attempt to extract Object element with Id '{}' : {}";
				if (LOG.isDebugEnabled()) {
					LOG.warn(errorMessage, id, e.getMessage(), e);
				} else {
					LOG.warn(errorMessage, id, e.getMessage());
				}
			}
		}
		return null;
	}

	/**
	 * Gets ds:Manifest by its Id from the ds:Signature element
	 *
	 * @param signatureElement {@link Element} the signature element to extract the signed ds:Manifest from
	 * @param id {@link String} manifest Id
	 * @return {@link Element} Manifest element
	 */
	public static Element getManifestById(Element signatureElement, String id) {
		if (Utils.isStringNotBlank(id)) {
			try {
				String manifestById = XMLDSigPath.MANIFEST_PATH + DomUtils.getXPathByIdAttribute(id);
				return DomUtils.getElement(signatureElement, manifestById);
			} catch (Exception e) {
				String errorMessage = "An error occurred on attempt to extract Manifest element with Id '{}' : {}";
				if (LOG.isDebugEnabled()) {
					LOG.warn(errorMessage, id, e.getMessage(), e);
				} else {
					LOG.warn(errorMessage, id, e.getMessage());
				}
			}
		}
		return null;
	}

	/**
	 * Initializes a Manifest object from the provided ds:Manifest element
	 *
	 * @param manifestElement {@link Element} ds:Manifest element
	 * @return {@link Manifest} object
	 * @throws XMLSecurityException if en error occurs in an attempt to initialize the Manifest object
	 */
	public static Manifest initManifest(Element manifestElement) throws XMLSecurityException {
		return new Manifest(manifestElement, "");
	}

	/**
	 * Initializes a Manifest object from the provided ds:Manifest element with a provided {@code detachedContents}
	 *
	 * @param manifestElement {@link Element} ds:Manifest element
	 * @param detachedContents a list of {@link DSSDocument}s representing a detached content
	 * @return {@link Manifest} object
	 * @throws XMLSecurityException if en error occurs in an attempt to initialize the Manifest object
	 */
	public static Manifest initManifestWithDetachedContent(Element manifestElement, List<DSSDocument> detachedContents) throws XMLSecurityException {
		final Manifest manifest = initManifest(manifestElement);
		initManifestDetachedContent(manifest, detachedContents);
		return manifest;
	}

	/**
	 * Initializes detached content within the given {@code manifest}
	 *
	 * @param manifest {@link Manifest} to initialize detached content in
	 * @param detachedContents a list of {@link DSSDocument}s
	 */
	public static void initManifestDetachedContent(Manifest manifest, List<DSSDocument> detachedContents) {
		if (Utils.isCollectionNotEmpty(detachedContents)) {
			for (DigestAlgorithm digestAlgorithm : getReferenceDigestAlgos(manifest.getElement())) {
				manifest.addResourceResolver(new DetachedSignatureResolver(detachedContents, digestAlgorithm));
			}
		}
	}
	
	/**
	 * Extracts signing certificate's public key from KeyInfo element of a given signature if present
	 * NOTE: can return null (the value is optional)
	 * 
	 * @param signatureElement {@link Element} representing a signature to get KeyInfo signing certificate for
	 * @return {@link PublicKey} of the signature extracted from KeyInfo element if present
	 */
	public static PublicKey getKeyInfoSigningCertificatePublicKey(final Element signatureElement) {
		Element keyInfoElement = DomUtils.getElement(signatureElement, XMLDSigPath.KEY_INFO_PATH);
		if (keyInfoElement != null) {
			try {
				KeyInfo keyInfo = new KeyInfo(keyInfoElement, "");
				return keyInfo.getPublicKey();
			} catch (XMLSecurityException e) {
				LOG.warn("Unable to extract signing certificate's public key. Reason : {}", e.getMessage(), e);
			}
		}
		LOG.warn("Unable to extract the public key. Reason : KeyInfo element is null");
		return null;
	}
	
	/**
	 * Creates and returns a counter signature found in the {@code counterSignatureElement}
	 * 
	 * @param counterSignatureElement {@link Element} {@code <ds:CounterSignature>} element
	 * @param masterSignature {@link XAdESSignature} master signature containing the counter signature
	 * @return {@link XAdESSignature}
	 */
	public static XAdESSignature createCounterSignature(Element counterSignatureElement, XAdESSignature masterSignature) {
		try {
			/*
			 * 5.2.7.2 Enveloped countersignatures: the CounterSignature qualifying property
			 * 
			 * The CounterSignature qualifying property shall contain one countersignature 
			 * of the XAdES signature where CounterSignature is incorporated. 
			 */
			final Node counterSignatureNode = DomUtils.getNode(counterSignatureElement, XMLDSigPath.SIGNATURE_PATH);
			
			// Verify that the element is a proper signature by trying to build a XAdESSignature out of it
			final XAdESSignature xadesCounterSignature = new XAdESSignature((Element) counterSignatureNode, masterSignature.getXAdESPathsHolders());
			xadesCounterSignature.setSignatureFilename(masterSignature.getSignatureFilename());
			xadesCounterSignature.setDetachedContents(masterSignature.getDetachedContents());
			if (isCounterSignature(xadesCounterSignature)) {
				xadesCounterSignature.setMasterSignature(masterSignature);
				return xadesCounterSignature;
			}
			
		} catch (Exception e) {
			String errorMessage = "An error occurred during counter signature extraction. The element entry is skipped. Reason : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, e.getMessage());
			}
		}
		
		return null;
	}

	/**
	 * This method verifies whether a given signature is a countersignature.
	 *
	 * From ETSI TS 101 903 V1.4.2: - The signature's ds:SignedInfo element MUST contain one ds:Reference element
	 * referencing the ds:Signature element of the
	 * embedding and countersigned XAdES signature - The content of the ds:DigestValue in the aforementioned
	 * ds:Reference element of the countersignature MUST
	 * be the base-64 encoded digest of the complete (and canonicalized) ds:SignatureValue element (i.e. including the
	 * starting and closing tags) of the
	 * embedding and countersigned XAdES signature.
	 *
	 * @param xadesCounterSignature {@link XAdESSignature} a signature extracted from {@code <ds:CounterSignature>} element
	 * @return TRUE if the current XAdES Signature contains a coutner signature reference, FALSE otherwise
	 */
	private static boolean isCounterSignature(final XAdESSignature xadesCounterSignature) {
		final List<Reference> references = xadesCounterSignature.getReferences();
		for (final Reference reference : references) {
			if (isCounterSignature(reference, xadesCounterSignature.getXAdESPaths())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns a NodeList of all "ds:Signature" elements found in the {@code documentNode}
	 * 
	 * @param documentNode {@link Node} the XML document or its part
	 * @return {@link NodeList}
	 */
	public static NodeList getAllSignaturesExceptCounterSignatures(Node documentNode) {
		return DomUtils.getNodeList(documentNode, XAdES132Path.ALL_SIGNATURE_WITH_NO_COUNTERSIGNATURE_AS_PARENT_PATH);
	}

	/**
	 * Returns a NodeList of all "xades:EncapsulatedTimeStamp" elements found in the {@code documentNode}
	 *
	 * @param documentNode {@link Node} the XML document or its part
	 * @return {@link NodeList}
	 */
	public static NodeList getAllEncapsulatedTimestamps(Node documentNode) {
		return DomUtils.getNodeList(documentNode, XAdES132Path.ALL_ENCAPSULATED_TIMESTAMP_PARENT_PATH);
	}

	/**
	 * Returns a NodeList of "ds:Reference" elements
	 * 
	 * @param signatureElement {@link Node} representing a ds:Signature node
	 * @return {@link NodeList}
	 */
	public static NodeList getReferenceNodeList(Node signatureElement) {
		return DomUtils.getNodeList(signatureElement, XMLDSigPath.SIGNED_INFO_REFERENCE_PATH);
	}

	/**
	 * Returns the expected dereferencing output for the provided
	 * {@code DSSReference}
	 * 
	 * @param reference {@link DSSReference} to get OutputType for
	 * @return {@link ReferenceOutputType}
	 */
	public static ReferenceOutputType getReferenceOutputType(final DSSReference reference) {
		ReferenceOutputType outputType = getDereferenceOutputType(reference.getUri());
		if (Utils.isCollectionNotEmpty(reference.getTransforms())) {
			for (DSSTransform transform : reference.getTransforms()) {
				String algorithmUri = transform.getAlgorithm();
				outputType = getTransformOutputType(algorithmUri);
			}
		}
		return outputType;
	}

	/**
	 * Returns the expected dereferencing output for the provided {@code Reference}
	 * 
	 * @param reference {@link Reference} to get OutputType for
	 * @return {@link ReferenceOutputType}
	 * @throws XMLSecurityException if an exception occurs
	 */
	public static ReferenceOutputType getReferenceOutputType(final Reference reference) throws XMLSecurityException {
		ReferenceOutputType outputType = getDereferenceOutputType(reference.getURI());
		Transforms transforms = reference.getTransforms();
		if (transforms != null) {
			for (int ii = 0; ii < transforms.getLength(); ii++) {
				Transform transform = transforms.item(ii);
				outputType = getTransformOutputType(transform.getURI());
			}
		}
		return outputType;
	}
	
	private static ReferenceOutputType getDereferenceOutputType(String referenceUri) {
		return isSameDocumentReference(referenceUri) ? ReferenceOutputType.NODE_SET : ReferenceOutputType.OCTET_STREAM;
	}
	
	private static ReferenceOutputType getTransformOutputType(String algorithmUri) {
		return transformsWithNodeSetOutput.contains(algorithmUri) ? ReferenceOutputType.NODE_SET : ReferenceOutputType.OCTET_STREAM;
	}

	/**
	 * Applies transforms on the node and returns the byte array to be used for a
	 * digest computation
	 * 
	 * NOTE: returns the original node binaries, if the list of {@code transforms}
	 * is empty
	 * 
	 * @param node         {@link Node} to apply transforms on
	 * @param transforms   a list of {@link DSSTransform}s to execute on the node
	 * @return a byte array, representing a content obtained after transformations
	 */
	public static byte[] applyTransforms(final Node node, final List<DSSTransform> transforms) {
		byte[] bytes = DSSUtils.EMPTY_BYTE_ARRAY;
		if (Utils.isCollectionNotEmpty(transforms)) {
			DSSTransformOutput output = new DSSTransformOutput(node);
			Iterator<DSSTransform> iterator = transforms.iterator();
			while (iterator.hasNext()) {
				DSSTransform transform = iterator.next();
				output = transform.performTransform(output);
				bytes = output.getBytes();
				if (iterator.hasNext() && Utils.isArrayEmpty(bytes)) {
					throw new IllegalInputException(String.format(
							"Unable to perform the next transform. The %s produced an empty output!", transform));
				}
			}

			if (LOG.isDebugEnabled()) {
				LOG.debug("Reference bytes after transforms: ");
				LOG.debug(new String(bytes));
			}
			if (Utils.isArrayEmpty(bytes)) {
				LOG.warn("The output of reference transforms processing is an empty byte array!");
			}
			return bytes;
			
		} else {
			bytes = DomUtils.getNodeBytes(node);
		}
		return bytes;
	}
	/**
	 * Applies transforms on document content and returns the byte array to be used for a
	 * digest computation
	 * 
	 * NOTE: returns the original document binaries, if the list of {@code transforms}
	 * is empty. The {@code document} shall represent an XML content.
	 * 
	 * @param document     {@link DSSDocument} representing an XML to apply transforms on
	 * @param transforms   a list of {@link DSSTransform}s to execute on the node
	 * @return a byte array, representing a content obtained after transformations
	 */
	public static byte[] applyTransforms(final DSSDocument document, final List<DSSTransform> transforms) {
		return applyTransforms(DomUtils.buildDOM(document), transforms);
	}

	/**
	 * Returns a list of {@code DigestAlgorithm} for all references containing inside
	 * the provided {@code referenceContainer}
	 *
	 * @param referenceContainer {@link Element} containing the ds:Reference elements
	 * @return a set of {@link DigestAlgorithm}s
	 */
	public static Set<DigestAlgorithm> getReferenceDigestAlgos(Element referenceContainer) {
		final Set<DigestAlgorithm> digestAlgorithms = new HashSet<>();
		NodeList referenceNodeList = DomUtils.getNodeList(referenceContainer, XMLDSigPath.REFERENCE_PATH);
		for (int ii = 0; ii < referenceNodeList.getLength(); ii++) {
			Element referenceElement = (Element) referenceNodeList.item(ii);
			Digest digest = getDigestAndValue(referenceElement);
			if (digest != null) {
				digestAlgorithms.add(digest.getAlgorithm());
			}
		}
		return digestAlgorithms;
	}

	/**
	 * Returns a list of reference types
	 *
	 * @param referenceContainer {@link Element} containing the ds:Reference elements
	 * @return a list of {@link String} reference types
	 */
	public static List<String> getReferenceTypes(Element referenceContainer) {
		List<String> referenceTypes = new ArrayList<>();
		NodeList referenceNodeList = DomUtils.getNodeList(referenceContainer, XMLDSigPath.REFERENCE_PATH);
		for (int ii = 0; ii < referenceNodeList.getLength(); ii++) {
			Element referenceElement = (Element) referenceNodeList.item(ii);
			String type = referenceElement.getAttribute(XMLDSigAttribute.TYPE.getAttributeName());
			if (Utils.isStringNotEmpty(type)) {
				referenceTypes.add(type);
			}
		}
		return referenceTypes;
	}

	/**
	 * Extracts a list of {@code Reference}s from the given {@code Manifest} object
	 *
	 * NOTE: can be used also for a {@code SignedInfo} element
	 *
	 * @param manifest {@link Manifest}
	 * @return a list of {@link Reference}s
	 */
	public static List<Reference> extractReferences(Manifest manifest) {
		List<Reference> references = new ArrayList<>();
		final int numberOfReferences = manifest.getLength();
		for (int ii = 0; ii < numberOfReferences; ii++) {
			try {
				final Reference reference = manifest.item(ii);
				references.add(reference);
			} catch (XMLSecurityException e) {
				LOG.warn("Unable to retrieve reference #{} : {}", ii, e.getMessage());
			}
		}
		return references;
	}

	/**
	 * Returns the {@code Digest} extracted from the provided {@code reference}
	 *
	 * @param reference {@link Reference}
	 * @return {@link Digest}
	 */
	public static Digest getReferenceDigest(Reference reference) {
		try {
			final Digest digest = new Digest();
			digest.setValue(reference.getDigestValue());
			digest.setAlgorithm(
					DigestAlgorithm.forXML(reference.getMessageDigestAlgorithm().getAlgorithmURI()));
			return digest;
		} catch (XMLSecurityException e) {
			LOG.warn("Unable to extract Digest from a reference with Id [{}] : {}",
					reference.getId(), e.getMessage(), e);
			return null;
		}
	}

	/**
	 * This method retrieves an Id attribute value of the given reference, when applicable
	 *
	 * NOTE: Method is used due to Apache Santuario Signature returning an empty string instead of null result.
	 *
	 * @param reference {@link Reference} to get value of Id attribute
	 * @return {@link String} Id attribute value if available, NULL otherwise
	 */
	public static String getReferenceId(Reference reference) {
		if (reference != null) {
			Element element = reference.getElement();
			if (element != null) {
				return getAttribute(element, XMLDSigAttribute.ID.getAttributeName());
			}
		}
		return null;
	}

	/**
	 * This method retrieves a URI attribute value of the given reference, when applicable
	 *
	 * NOTE: Method is used due to Apache Santuario Signature returning an empty string instead of null result.
	 *
	 * @param reference {@link Reference} to get value of URI attribute
	 * @return {@link String} URI attribute value if available, NULL otherwise
	 */
	public static String getReferenceURI(Reference reference) {
		if (reference != null) {
			Element element = reference.getElement();
			if (element != null) {
				return getAttribute(element, XMLDSigAttribute.URI.getAttributeName());
			}
		}
		return null;
	}

	/**
	 * Checks if the original reference document content can be obtained (de-referenced)
	 *
	 * @param reference {@link Reference} to check
	 * @return TRUE if the de-referencing is succeeding, FALSE otherwise
	 */
	public static boolean isAbleToDeReferenceContent(Reference reference) {
		return getClosedContentsBeforeTransformation(reference) != null;
	}

	/**
	 * Checks if the reference with the {@code uri} occurs multiple times in the {@code document}
	 *
	 * @param document {@link Document} to be checked for a wrapping attack
	 * @param uri {@link String} the referenced uri to be verified
	 * @return TRUE if the reference is ambiguous (duplicated), FALSE otherwise
	 */
	public static boolean isReferencedContentAmbiguous(Document document, String uri) {
		if (Utils.isStringNotEmpty(uri)) {
			return !XMLUtils.protectAgainstWrappingAttack(document, DomUtils.getId(uri));
		}
		// empty URI means enveloped signature (unambiguous)
		return false;
	}

	/**
	 * Incorporates a ds:Transforms element into the given parent {@code element}
	 *
	 * @param parentElement {@link Element} to incorporate ds:Transforms into
	 * @param transforms a list of {@link DSSTransform}s to be incorporated
	 * @param namespace {@link DSSNamespace} to use
	 */
	public static void incorporateTransforms(final Element parentElement, List<DSSTransform> transforms, DSSNamespace namespace) {
		if (Utils.isCollectionNotEmpty(transforms)) {
			final Document documentDom = parentElement.getOwnerDocument();
			final Element transformsDom = DomUtils.createElementNS(documentDom, namespace, XMLDSigElement.TRANSFORMS);
			parentElement.appendChild(transformsDom);
			for (final DSSTransform dssTransform : transforms) {
				dssTransform.createTransform(documentDom, transformsDom);
			}
		}
	}

	/**
	 * This method creates the ds:DigestMethod DOM object
	 *
	 * <pre>
	 * {@code
	 * 		<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
	 * }
	 * </pre>
	 *
	 * @param parentElement
	 *             {@link Element}the parent element
	 * @param digestAlgorithm
	 *            {@link DigestAlgorithm} the digest algorithm
	 * @param namespace
	 *            {@link DSSNamespace} to use
	 */
	public static void incorporateDigestMethod(final Element parentElement, DigestAlgorithm digestAlgorithm, DSSNamespace namespace) {
		final Document documentDom = parentElement.getOwnerDocument();
		final Element digestMethodDom = DomUtils.addElement(documentDom, parentElement, namespace, XMLDSigElement.DIGEST_METHOD);
		digestMethodDom.setAttribute(XMLDSigAttribute.ALGORITHM.getAttributeName(), digestAlgorithm.getUri());
	}

	/**
	 * This method creates the ds:DigestValue DOM object.
	 *
	 * <pre>
	 * {@code
	 * 		<ds:DigestValue>fj8SJujSXU4fi342bdtiKVbglA0=</ds:DigestValue>
	 * }
	 * </pre>
	 *
	 * @param parentDom
	 *            {@link Element} the parent element
	 * @param base64EncodedDigestBytes
	 *            {@link String} representing a base64-encoded Digest value
	 * @param namespace
	 *            {@link DSSNamespace}
	 */
	public static void incorporateDigestValue(final Element parentDom, String base64EncodedDigestBytes, DSSNamespace namespace) {
		final Document documentDom = parentDom.getOwnerDocument();
		final Element digestValueDom = DomUtils.createElementNS(documentDom, namespace, XMLDSigElement.DIGEST_VALUE);

		final Text textNode = documentDom.createTextNode(base64EncodedDigestBytes);
		digestValueDom.appendChild(textNode);
		parentDom.appendChild(digestValueDom);
	}

	/**
	 * Returns params.referenceDigestAlgorithm if exists, params.digestAlgorithm otherwise
	 *
	 * @param params {@link XAdESSignatureParameters}
	 * @return {@link DigestAlgorithm}
	 */
	public static DigestAlgorithm getReferenceDigestAlgorithmOrDefault(XAdESSignatureParameters params) {
		DigestAlgorithm digestAlgorithm = params.getReferenceDigestAlgorithm() != null ? params.getReferenceDigestAlgorithm() : params.getDigestAlgorithm();
		if (digestAlgorithm == null || digestAlgorithm.getUri() == null) {
			throw new IllegalArgumentException(String.format("The Reference DigestAlgorithm '%s' is not supported for XAdES creation! " +
					"Define another algorithm within #setReferenceDigestAlgorithm method.", digestAlgorithm));
		}
		return digestAlgorithm;
	}

	/**
     * This method produces a copy of the document and returns an element by the defined {@code xpathString}.
     * This method can be used as a workaround for canonicalization, as namespaces are not added to canonicalizer
     * for new created elements.
     * The issue was reported on: <a href="https://issues.apache.org/jira/browse/SANTUARIO-139">SANTUARIO-139</a>
     *
     * @param document {@link Document}
     * @param elementId {@link String} optional element Id to start XPath expression from
     * @param xpathString {@link String} corresponding to an XPath of element to be returned
     * @return {@link Element}
     */
	public static Element ensureNamespacesDefined(Document document, String elementId, String xpathString) {
		final byte[] serializedDoc = DomUtils.serializeNode(document);
		Document recreatedDocument = DomUtils.buildDOM(serializedDoc);
		Element element = recreatedDocument.getDocumentElement();
		if (Utils.isStringNotEmpty(elementId)) {
			element = DomUtils.getElementById(recreatedDocument, elementId);
		}
		return DomUtils.getElement(element, xpathString);
	}

	/**
	 * This method returns a name of the linked document to the reference (when applicable)
	 *
	 * @param reference {@link Reference} to get a name of the linked document for
	 * @return {@link String} document name
	 */
	public static String getDocumentName(Reference reference) {
		try {
			XMLSignatureInput xmlSignatureInput = getClosedContentsBeforeTransformation(reference);
			if (xmlSignatureInput instanceof DSSDocumentXMLSignatureInput) {
				return ((DSSDocumentXMLSignatureInput) xmlSignatureInput).getDocumentName();
			}
		} catch (Exception e) {
			String errorMessage = "Unable to verify matching document name for a reference with Id [{}] : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, reference.getId(), e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, reference.getId(), e.getMessage());
			}
		}
		return null;
	}

	/**
	 * The close method is a workaround for the issue originating from
	 * {@link <a href="https://issues.apache.org/jira/browse/SANTUARIO-622">SANTUARIO-622</a>},
	 * as the {@code XMLSignatureInput} instantiated with an {@code InputStream}, does not close
	 * the {@code InputStream}, unless it is consumed.
	 *
	 * @param reference {@link Reference}
	 * @return {@link XMLSignatureInput}
	 */
	private static XMLSignatureInput getClosedContentsBeforeTransformation(Reference reference) {
		try {
			XMLSignatureInput xmlSignatureInput = reference.getContentsBeforeTransformation();
			if (xmlSignatureInput != null) {
				Utils.closeQuietly(xmlSignatureInput.getOctetStreamReal());
			}
			return xmlSignatureInput;

		} catch (Exception e) {
			String errorMessage = "Unable to get contents before transformation for a reference with Id '{}' : {}";
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, reference.getId(), e.getMessage(), e);
			} else {
				LOG.warn(errorMessage, reference.getId(), e.getMessage());
			}
			return null;
		}
	}

}

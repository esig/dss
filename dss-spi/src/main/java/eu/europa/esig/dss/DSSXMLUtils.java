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
package eu.europa.esig.dss;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.CanonicalizationException;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.c14n.InvalidCanonicalizerException;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * Utility class that contains some XML related method.
 *
 */
public final class DSSXMLUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSXMLUtils.class);

	public static final String ID_ATTRIBUTE_NAME = "id";
	public static final String XAD_ESV141_XSD = "/XAdESv141.xsd";

	private static DocumentBuilderFactory dbFactory;

	private static final XPathFactory factory = XPathFactory.newInstance();

	private static NamespaceContextMap namespacePrefixMapper;

	private static final Map<String, String> namespaces;

	private static final Set<String> transforms;

	private static final Set<String> canonicalizers;

	static {

		Init.init();

		namespacePrefixMapper = new NamespaceContextMap();
		namespaces = new HashMap<String, String>();
		registerDefaultNamespaces();

		transforms = new HashSet<String>();
		registerDefaultTransforms();

		canonicalizers = new HashSet<String>();
		registerDefaultCanonicalizers();
	}

	private static Schema schema = null;

	/**
	 * This method registers the default namespaces.
	 */
	private static void registerDefaultNamespaces() {

		registerNamespace("ds", XMLSignature.XMLNS);
		registerNamespace("dsig", XMLSignature.XMLNS);
		registerNamespace("xades", XAdESNamespaces.XAdES); // 1.3.2
		registerNamespace("xades141", XAdESNamespaces.XAdES141);
		registerNamespace("xades122", XAdESNamespaces.XAdES122);
		registerNamespace("xades111", XAdESNamespaces.XAdES111);
		registerNamespace("asic", ASiCNamespaces.ASiC);
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
	 * This method allows to register a namespace and associated prefix. If the prefix exists already it is replaced.
	 *
	 * @param prefix    namespace prefix
	 * @param namespace namespace
	 * @return true if this map did not already contain the specified element
	 */
	public static boolean registerNamespace(final String prefix, final String namespace) {

		final String put = namespaces.put(prefix, namespace);
		namespacePrefixMapper.registerNamespace(prefix, namespace);
		return put == null;
	}

	/**
	 * This method allows to register a transformation.
	 *
	 * @param transformURI the URI of transform
	 * @return true if this set did not already contain the specified element
	 */
	public static boolean registerTransform(final String transformURI) {

		final boolean added = transforms.add(transformURI);
		return added;
	}

	/**
	 * This method allows to register a canonicalizer.
	 *
	 * @param c14nAlgorithmURI the URI of canonicalization algorithm
	 * @return true if this set did not already contain the specified element
	 */
	public static boolean registerCanonicalizer(final String c14nAlgorithmURI) {

		final boolean added = canonicalizers.add(c14nAlgorithmURI);
		return added;
	}

	/**
	 * @param xpathString XPath query string
	 * @return
	 */
	private static XPathExpression createXPathExpression(final String xpathString) {

		/* XPath */
		final XPath xpath = factory.newXPath();
		xpath.setNamespaceContext(namespacePrefixMapper);
		try {
			final XPathExpression expr = xpath.compile(xpathString);
			return expr;
		} catch (XPathExpressionException ex) {
			throw new DSSException(ex);
		}
	}

	/**
	 * Return the Element corresponding to the XPath query.
	 *
	 * @param xmlNode     The node where the search should be performed.
	 * @param xPathString XPath query string
	 * @return
	 */
	public static Element getElement(final Node xmlNode, final String xPathString) {

		return (Element) getNode(xmlNode, xPathString);
	}

	/**
	 * Return the Node corresponding to the XPath query.
	 *
	 * @param xmlNode     The node where the search should be performed.
	 * @param xPathString XPath query string
	 * @return
	 */
	public static Node getNode(final Node xmlNode, final String xPathString) {

		final NodeList list = getNodeList(xmlNode, xPathString);
		if (list.getLength() > 1) {
			throw new DSSException("More than one result for XPath: " + xPathString);
		}
		return list.item(0);
	}

	/**
	 * This method returns the list of children's names for a given {@code Node}.
	 *
	 * @param xmlNode     The node where the search should be performed.
	 * @param xPathString XPath query string
	 * @return {@code List} of children's names
	 */
	public static List<String> getChildrenNames(final Node xmlNode, final String xPathString) {

		ArrayList<String> childrenNames = new ArrayList<String>();

		final Element element = DSSXMLUtils.getElement(xmlNode, xPathString);
		if (element != null) {

			final NodeList unsignedProperties = element.getChildNodes();
			for (int ii = 0; ii < unsignedProperties.getLength(); ++ii) {

				final Node node = unsignedProperties.item(ii);
				childrenNames.add(node.getLocalName());
			}
		}
		return childrenNames;
	}

	/**
	 * Returns the NodeList corresponding to the XPath query.
	 *
	 * @param xmlNode     The node where the search should be performed.
	 * @param xPathString XPath query string
	 * @return
	 * @throws XPathExpressionException
	 */
	public static NodeList getNodeList(final Node xmlNode, final String xPathString) {

		try {

			final XPathExpression expr = createXPathExpression(xPathString);
			final NodeList evaluated = (NodeList) expr.evaluate(xmlNode, XPathConstants.NODESET);
			return evaluated;
		} catch (XPathExpressionException e) {

			throw new DSSException(e);
		}
	}

	/**
	 * Returns the String value of the corresponding to the XPath query.
	 *
	 * @param xmlNode     The node where the search should be performed.
	 * @param xPathString XPath query string
	 * @return string value of the XPath query
	 * @throws XPathExpressionException
	 */
	public static String getValue(final Node xmlNode, final String xPathString) {

		try {

			final XPathExpression xPathExpression = createXPathExpression(xPathString);
			final String string = (String) xPathExpression.evaluate(xmlNode, XPathConstants.STRING);
			return string.trim();
		} catch (XPathExpressionException e) {

			throw new DSSException(e);
		}
	}

	/**
	 * Returns the number of found elements based on the XPath query.
	 *
	 * @param xmlNode
	 * @param xPathString
	 * @return
	 */
	public static int count(final Node xmlNode, final String xPathString) {
		try {
			final XPathExpression xPathExpression = createXPathExpression(xPathString);
			final Double number = (Double) xPathExpression.evaluate(xmlNode, XPathConstants.NUMBER);
			return number.intValue();
		} catch (XPathExpressionException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Returns true if the xpath query contains something
	 *
	 * @param xmlNode
	 * @param xPathString
	 * @return
	 */
	public static boolean isNotEmpty(final Node xmlNode, final String xPathString) {
		// xpath suffix allows to skip text nodes and empty lines
		NodeList nodeList = getNodeList(xmlNode, xPathString + "/child::node()[not(self::text())]");
		if ((nodeList != null) && (nodeList.getLength() > 0)) {
			return true;
		}
		return false;
	}

	/**
	 * Document Object Model (DOM) Level 3 Load and Save Specification See: http://www.w3.org/TR/2004/REC-DOM-Level-3-LS-20040407/
	 *
	 * @param xmlNode The node to be serialized.
	 * @return
	 */
	public static byte[] serializeNode(final Node xmlNode) {

		try {

			final DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
			final DOMImplementationLS impl = (DOMImplementationLS) registry.getDOMImplementation("LS");
			final LSSerializer writer = impl.createLSSerializer();

			final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
			final LSOutput output = impl.createLSOutput();
			output.setByteStream(buffer);
			writer.write(xmlNode, output);

			final byte[] bytes = buffer.toByteArray();
			return bytes;
		} catch (ClassNotFoundException e) {
			throw new DSSException(e);
		} catch (InstantiationException e) {
			throw new DSSException(e);
		} catch (IllegalAccessException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * An ID attribute can only be dereferenced if it is declared in the validation context. This behaviour is caused by the fact that the attribute does not have attached type of
	 * information. Another solution is to parse the XML against some DTD or XML schema. This process adds the necessary type of information to each ID attribute.
	 * This method is useful to carry out tests with different signature provider.
	 *
	 * @param context
	 * @param element
	 */
	public static void recursiveIdBrowse(final DOMValidateContext context, final Element element) {

		for (int ii = 0; ii < element.getChildNodes().getLength(); ii++) {

			final Node node = element.getChildNodes().item(ii);
			if (node.getNodeType() == Node.ELEMENT_NODE) {

				final Element childElement = (Element) node;
				setIDIdentifier(context, childElement);
				recursiveIdBrowse(context, childElement);
			}
		}
	}

	/**
	 * An ID attribute can only be dereferenced if it is declared in the validation context. This behaviour is caused by the fact that the attribute does not have attached type of
	 * information. Another solution is to parse the XML against some DTD or XML schema. This process adds the necessary type of information to each ID attribute.
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
	 * If this method finds an attribute with names ID (case-insensitive) then it is returned. If there is more than one ID attributes then the first one is returned.
	 *
	 * @param element to be checked
	 * @return the ID attribute value or null
	 */
	public static String getIDIdentifier(final Element element) {

		final NamedNodeMap attributes = element.getAttributes();
		for (int jj = 0; jj < attributes.getLength(); jj++) {

			final Node item = attributes.item(jj);
			final String localName = item.getNodeName();
			if (localName != null) {
				final String id = localName.toLowerCase();
				if (ID_ATTRIBUTE_NAME.equals(id)) {

					return item.getTextContent();
				}
			}
		}
		return null;
	}

	/**
	 * If this method finds an attribute with names ID (case-insensitive) then declares it to be a user-determined ID attribute.
	 *
	 * @param childElement
	 */
	public static void setIDIdentifier(final DOMValidateContext context, final Element childElement) {

		final NamedNodeMap attributes = childElement.getAttributes();
		for (int jj = 0; jj < attributes.getLength(); jj++) {

			final Node item = attributes.item(jj);
			final String localName = item.getNodeName();
			if (localName != null) {
				final String id = localName.toLowerCase();
				if (ID_ATTRIBUTE_NAME.equals(id)) {

					context.setIdAttributeNS(childElement, null, localName);
					break;
				}
			}
		}
	}

	/**
	 * If this method finds an attribute with names ID (case-insensitive) then declares it to be a user-determined ID attribute.
	 *
	 * @param childElement
	 */
	public static void setIDIdentifier(final Element childElement) {

		final NamedNodeMap attributes = childElement.getAttributes();
		for (int jj = 0; jj < attributes.getLength(); jj++) {

			final Node item = attributes.item(jj);
			final String localName = item.getNodeName();
			if (localName != null) {
				final String id = localName.toLowerCase();
				if (ID_ATTRIBUTE_NAME.equals(id)) {

					childElement.setIdAttribute(localName, true);
					break;
				}
			}
		}
	}

	/**
	 * Guarantees that the xmlString builder has been created.
	 *
	 * @throws ParserConfigurationException
	 */
	private static void ensureDocumentBuilder() throws DSSException {

		if (dbFactory != null) {
			return;
		}
		dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		try {
			// disable external entities
			dbFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
			dbFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
			dbFactory.setXIncludeAware(false);
			dbFactory.setExpandEntityReferences(false);
		} catch (ParserConfigurationException e) {
			throw new DSSException(e);
		}
	}

	public static TransformerFactory getSecureTransformerFactory() {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		try {
			transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		} catch (TransformerConfigurationException e) {
			throw new DSSException(e);
		}
		return transformerFactory;
	}

	/**
	 * Creates the new empty Document.
	 *
	 * @return
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 */
	public static Document buildDOM() {

		ensureDocumentBuilder();

		try {
			return dbFactory.newDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on the XML string.
	 *
	 * @param xmlString The string representing the dssDocument to be created.
	 * @return
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 */
	public static Document buildDOM(final String xmlString) throws DSSException {

		final InputStream input = new ByteArrayInputStream(DSSUtils.getUtf8Bytes(xmlString));
		return buildDOM(input);
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on byte array.
	 *
	 * @param bytes The bytes array representing the dssDocument to be created.
	 * @return
	 * @throws ParserConfigurationException
	 * @throws IOException
	 * @throws SAXException
	 */
	public static Document buildDOM(final byte[] bytes) throws DSSException {

		final InputStream input = new ByteArrayInputStream(bytes);
		return buildDOM(input);
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on the XML inputStream.
	 *
	 * @param inputStream The inputStream stream representing the dssDocument to be created.
	 * @return
	 * @throws SAXException
	 * @throws IOException
	 */
	public static Document buildDOM(final InputStream inputStream) throws DSSException {

		try {
			ensureDocumentBuilder();

			final Document rootElement = dbFactory.newDocumentBuilder().parse(inputStream);
			return rootElement;
		} catch (SAXParseException e) {
			throw new DSSException(e);
		} catch (SAXException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		} catch (ParserConfigurationException e) {
			throw new DSSException(e);
		} finally {
			IOUtils.closeQuietly(inputStream);
		}
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on the {@link eu.europa.esig.dss.DSSDocument}.
	 *
	 * @param dssDocument The DSS representation of the document from which the dssDocument is created.
	 * @return
	 * @throws DSSException
	 */
	public static Document buildDOM(final DSSDocument dssDocument) throws DSSException {

		final InputStream input = dssDocument.openStream();
		try {

			final Document doc = buildDOM(input);
			return doc;
		} finally {
			IOUtils.closeQuietly(input);
		}
	}

	/**
	 * This method says if the framework can canonicalize an XML data with the provided method.
	 *
	 * @param canonicalizationMethod the canonicalization method to be checked
	 * @return true if it is possible to canonicalize false otherwise
	 */
	public static boolean canCanonicalize(final String canonicalizationMethod) {

		if (transforms.contains(canonicalizationMethod)) {
			return false;
		}
		final boolean contains = canonicalizers.contains(canonicalizationMethod);
		return contains;
	}

	/**
	 * This method canonicalizes the given array of bytes using the {@code canonicalizationMethod} parameter.
	 *
	 * @param canonicalizationMethod canonicalization method
	 * @param toCanonicalizeBytes    array of bytes to canonicalize
	 * @return array of canonicalized bytes
	 * @throws DSSException if any error is encountered
	 */
	public static byte[] canonicalize(final String canonicalizationMethod, final byte[] toCanonicalizeBytes) throws DSSException {

		try {

			final Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
			return c14n.canonicalize(toCanonicalizeBytes);
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method canonicalizes the given {@code Node}.
	 *
	 * @param canonicalizationMethod canonicalization method
	 * @param node                   {@code Node} to canonicalize
	 * @return array of canonicalized bytes
	 */
	public static byte[] canonicalizeSubtree(final String canonicalizationMethod, final Node node) {

		try {

			final Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
			final byte[] canonicalized = c14n.canonicalizeSubtree(node);
			return canonicalized;
		} catch (InvalidCanonicalizerException e) {
			throw new DSSException(e);
		} catch (CanonicalizationException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method canonicalizes the given {@code NodeList}.
	 *
	 * @param canonicalizationMethod canonicalization method
	 * @param nodeList               {@code NodeList} to canonicalize
	 * @return array of canonicalized bytes
	 */
	public static byte[] canonicalizeXPathNodeSet(final String canonicalizationMethod, final Set<Node> nodeList) {

		try {

			final Canonicalizer c14n = Canonicalizer.getInstance(canonicalizationMethod);
			final byte[] canonicalized = c14n.canonicalizeXPathNodeSet(nodeList);
			return canonicalized;
		} catch (InvalidCanonicalizerException e) {
			throw new DSSException(e);
		} catch (CanonicalizationException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method creates and adds a new XML {@code Element} with text value
	 *
	 * @param document  root document
	 * @param parentDom parent node
	 * @param namespace namespace
	 * @param name      element name
	 * @param value     element text node value
	 * @return added element
	 */
	public static Element addTextElement(final Document document, final Element parentDom, final String namespace, final String name, final String value) {

		final Element dom = document.createElementNS(namespace, name);
		parentDom.appendChild(dom);
		final Text valueNode = document.createTextNode(value);
		dom.appendChild(valueNode);
		return dom;
	}

	/**
	 * This method creates and adds a new XML {@code Element}
	 *
	 * @param document  root document
	 * @param parentDom parent node
	 * @param namespace namespace
	 * @param name      element name
	 * @return added element
	 */
	public static Element addElement(final Document document, final Element parentDom, final String namespace, final String name) {

		final Element dom = document.createElementNS(namespace, name);
		parentDom.appendChild(dom);
		return dom;
	}

	public static byte[] transformDomToByteArray(final Document documentDom) {

		try {

			final TransformerFactory transformerFactory = TransformerFactory.newInstance();
			final Transformer transformer = transformerFactory.newTransformer();
			final String xmlEncoding = documentDom.getXmlEncoding();
			if (StringUtils.isNotBlank(xmlEncoding)) {
				transformer.setOutputProperty(OutputKeys.ENCODING, xmlEncoding);
			}
			final DOMSource source = new DOMSource(documentDom);

			final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			final StreamResult streamResult = new StreamResult(byteArrayOutputStream);
			transformer.transform(source, streamResult);
			byte[] byteArray = byteArrayOutputStream.toByteArray();
			return byteArray;
		} catch (final TransformerException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method sets a text node to the given DOM element.
	 *
	 * @param document  root document
	 * @param parentDom parent node
	 * @param text      text to be added
	 */
	public static void setTextNode(final Document document, final Element parentDom, final String text) {

		final Text textNode = document.createTextNode(text);
		parentDom.appendChild(textNode);
	}

	/**
	 * Creates a DOM Document object of the specified type with its document element.
	 *
	 * @param namespaceURI  the namespace URI of the document element to create or null
	 * @param qualifiedName the qualified name of the document element to be created or null
	 * @param element       document {@code Element}
	 * @return {@code Document}
	 */
	public static Document createDocument(final String namespaceURI, final String qualifiedName, final Element element) {
		ensureDocumentBuilder();

		DOMImplementation domImpl;
		try {
			domImpl = dbFactory.newDocumentBuilder().getDOMImplementation();
		} catch (ParserConfigurationException e) {
			throw new DSSException(e);
		}
		final Document newDocument = domImpl.createDocument(namespaceURI, qualifiedName, null);
		final Element newElement = newDocument.getDocumentElement();
		newDocument.adoptNode(element);
		newElement.appendChild(element);

		return newDocument;
	}

	/**
	 * Creates a DOM document without document element.
	 *
	 * @param namespaceURI  the namespace URI of the document element to create or null
	 * @param qualifiedName the qualified name of the document element to be created or null
	 * @return {@code Document}
	 */
	public static Document createDocument(final String namespaceURI, final String qualifiedName) {
		ensureDocumentBuilder();

		DOMImplementation domImpl;
		try {
			domImpl = dbFactory.newDocumentBuilder().getDOMImplementation();
		} catch (ParserConfigurationException e) {
			throw new DSSException(e);
		}

		return domImpl.createDocument(namespaceURI, qualifiedName, null);
	}


	/**
	 * Creates a DOM Document object of the specified type with its document elements.
	 *
	 * @param namespaceURI
	 * @param qualifiedName
	 * @param element1
	 * @param element2
	 * @return {@code Document}
	 */
	public static Document createDocument(final String namespaceURI, final String qualifiedName, final Element element1, final Element element2) {
		ensureDocumentBuilder();

		DOMImplementation domImpl;
		try {
			domImpl = dbFactory.newDocumentBuilder().getDOMImplementation();
		} catch (ParserConfigurationException e) {
			throw new DSSException(e);
		}
		final Document newDocument = domImpl.createDocument(namespaceURI, qualifiedName, null);
		final Element newElement = newDocument.getDocumentElement();
		newDocument.adoptNode(element1);
		newElement.appendChild(element1);

		newDocument.adoptNode(element2);
		newElement.appendChild(element2);

		return newDocument;
	}

	/**
	 * Converts a given {@code Date} to a new {@code XMLGregorianCalendar}.
	 *
	 * @param date the date to be converted
	 * @return the new {@code XMLGregorianCalendar} or null
	 */
	public static XMLGregorianCalendar createXMLGregorianCalendar(final Date date) {

		if (date == null) {
			return null;
		}
		final GregorianCalendar calendar = new GregorianCalendar();
		calendar.setTime(date);
		try {

			XMLGregorianCalendar xmlGregorianCalendar = DatatypeFactory.newInstance().newXMLGregorianCalendar(calendar);
			xmlGregorianCalendar.setFractionalSecond(null);
			xmlGregorianCalendar = xmlGregorianCalendar.normalize(); // to UTC = Zulu
			return xmlGregorianCalendar;
		} catch (DatatypeConfigurationException e) {

			// LOG.warn("Unable to properly convert a Date to an XMLGregorianCalendar",e);
		}
		return null;
	}

	/**
	 * This method allows to convert the given text (XML representation of a date) to the {@code Date}.
	 *
	 * @param text the text representing the XML date
	 * @return {@code Date} converted or null
	 */
	public static Date getDate(final String text) {

		try {

			final DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
			final XMLGregorianCalendar xmlGregorianCalendar = datatypeFactory.newXMLGregorianCalendar(text);
			return xmlGregorianCalendar.toGregorianCalendar().getTime();
		} catch (DatatypeConfigurationException e) {
			// do nothing
		}
		return null;
	}

	/**
	 * This method retrieves an element based on its ID
	 *
	 * @param currentDom the DOM in which the element has to be retrieved
	 * @param elementId  the specified ID
	 * @param namespace  the namespace to take into account
	 * @param tagName    the tagName of the element to find
	 * @return the
	 * @throws NullPointerException
	 */
	public static Element getElementById(Document currentDom, String elementId, String namespace, String tagName) throws NullPointerException {

		Element element = null;
		NodeList nodes = currentDom.getElementsByTagNameNS(namespace, tagName);

		for (int i = 0; i < nodes.getLength(); i++) {
			element = (Element) nodes.item(i);
			if (elementId.equals(DSSXMLUtils.getIDIdentifier(element))) {
				return element;
			}
		}
		if (element == null) {
			throw new NullPointerException();
		}
		return null;
	}

	/**
	 * This method allows to validate an XML against the XAdES XSD schema.
	 *
	 * @param streamSource {@code InputStream} XML to validate
	 * @return null if the XSD validates the XML, error message otherwise
	 */
	public static String validateAgainstXSD(final StreamSource streamSource) {

		try {

			if (schema == null) {
				schema = getSchema();
			}
			final Validator validator = schema.newValidator();
			validator.validate(streamSource);
			return StringUtils.EMPTY;
		} catch (Exception e) {
			LOG.warn("Error during the XML schema validation!", e);
			return e.getMessage();
		}
	}

	private static Schema getSchema() throws SAXException {

		final ResourceLoader resourceLoader = new ResourceLoader();
		final InputStream xadesXsd = resourceLoader.getResource(XAD_ESV141_XSD);
		final SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		return factory.newSchema(new StreamSource(xadesXsd));
	}

	/**
	 * This method allows to convert an XML {@code Node} to a {@code String}.
	 *
	 * @param node {@code Node} to be converted
	 * @return {@code String} representation of the node
	 */
	public static String xmlToString(final Node node) {

		try {

			final Source source = new DOMSource(node);
			final StringWriter stringWriter = new StringWriter();
			final Result result = new StreamResult(stringWriter);
			final TransformerFactory factory = TransformerFactory.newInstance();
			final Transformer transformer = factory.newTransformer();
			transformer.transform(source, result);
			return stringWriter.getBuffer().toString();
		} catch (TransformerConfigurationException e) {
			throw new DSSException(e);
		} catch (TransformerException e) {
			throw new DSSException(e);
		}
	}
}

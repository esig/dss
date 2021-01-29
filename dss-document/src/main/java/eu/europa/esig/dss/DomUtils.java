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

import eu.europa.esig.dss.definition.DSSAttribute;
import eu.europa.esig.dss.definition.DSSElement;
import eu.europa.esig.dss.definition.DSSNamespace;
import eu.europa.esig.dss.jaxb.common.XmlDefinerUtils;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

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
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * The utils for dealing with {@code org.w3c.dom} objects
 */
public final class DomUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DomUtils.class);

	/** Value used to pretty print xades signature */
	public static final int TRANSFORMER_INDENT_NUMBER = 4;

	/** The default value of the used Transformer */
	private static final String TRANSFORMER_METHOD_VALUE = "xml";

	/** The 'xmlns' opener */
	private static final String XNS_OPEN = "xmlns(";

	/** The 'xpointer' opener */
	private static final String XP_OPEN = "xpointer(";

	/** The 'xpointer' with id opener */
	private static final String XP_WITH_ID_OPEN = "#xpointer(id(";

	/** The staring binaries of an XML file */
	private static final byte[] xmlPreamble = new byte[] { '<' };

	/** The staring binaries of an XML file with BOM */
	private static final byte[] xmlWithBomPreample = new byte[] { -17, -69, -65, '<' }; // UTF-8 with BOM

	private DomUtils() {
	}

	/** The used DocumentBuilderFactory */
	private static DocumentBuilderFactory dbFactory;

	/** The used XPathFactory */
	private static final XPathFactory factory = XPathFactory.newInstance();

	/** Map containing the defined namespaces */
	private static NamespaceContextMap namespacePrefixMapper;

	static {
		namespacePrefixMapper = new NamespaceContextMap();

		dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		dbFactory.setXIncludeAware(false);
		dbFactory.setExpandEntityReferences(false);

		// disable external entities details :
		// https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet#Java
		setSecurityFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
		setSecurityFeature("http://xml.org/sax/features/external-general-entities", false);
		setSecurityFeature("http://xml.org/sax/features/external-parameter-entities", false);
		setSecurityFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
	}
	
	/**
	 * Enables a feature for the DocumentBuilderFactory
	 *
	 * @param feature {@link String} feature name (URL) to enable
	 * @throws ParserConfigurationException if an exception occurs
	 */
	public static void enableFeature(String feature) throws ParserConfigurationException {
		if (LOG.isDebugEnabled()) {
			LOG.debug("Enabling DocumentBuilderFactory feature [{}]...", feature);
		}
		setFeature(feature, true);
	}

	/**
	 * Disables a feature for the DocumentBuilderFactory
	 *
	 * @param feature {@link String} feature name (URL) to disable
	 * @throws ParserConfigurationException if an exception occurs
	 */
	public static void disableFeature(String feature) throws ParserConfigurationException {
		if (LOG.isDebugEnabled()) {
			LOG.debug("Disabling DocumentBuilderFactory feature [{}]...", feature);
		}
		setFeature(feature, false);
	}

	private static void setSecurityFeature(String property, boolean enable) {
		try {
			setFeature(property, enable);
		} catch (ParserConfigurationException e) {
			String message = String.format("SECURITY : unable to set feature %s = %s (more details in LOG debug)", property, enable);
			if (LOG.isDebugEnabled()) {
				LOG.debug(message, e);
			} else {
				LOG.warn(message);
			}
		}
	}

	private static void setFeature(String property, boolean enable) throws ParserConfigurationException {
		dbFactory.setFeature(property, enable);
	}

	/**
	 * This method allows to register a namespace and associated prefix. If the prefix exists already it is replaced.
	 *
	 * @param namespace
	 *            namespace object with the prefix and the URI
	 * @return true if this map did not already contain the specified element
	 */
	public static boolean registerNamespace(final DSSNamespace namespace) {
		return namespacePrefixMapper.registerNamespace(namespace.getPrefix(), namespace.getUri());
	}

	/**
	 * This method returns a new instance of TransformerFactory with secured features enabled
	 * 
	 * @return an instance of TransformerFactory with enabled secure features
	 */
	public static TransformerFactory getSecureTransformerFactory() {
		TransformerFactory transformerFactory = XmlDefinerUtils.getInstance().getSecureTransformerFactory();
		transformerFactory.setErrorListener(new DSSXmlErrorListener());
		return transformerFactory;
	}

	/**
	 * This method returns a new instance of Transformer with secured features enabled
	 * 
	 * @return an instance of Transformer with enabled secure features
	 */
	public static Transformer getSecureTransformer() {
		TransformerFactory transformerFactory = getSecureTransformerFactory();
		Transformer transformer = null;
		try {
			transformer = transformerFactory.newTransformer();
			transformer.setOutputProperty(OutputKeys.METHOD, TRANSFORMER_METHOD_VALUE);
		} catch (TransformerConfigurationException e) {
			throw new DSSException(e);
		}
		transformer.setErrorListener(new DSSXmlErrorListener());
		return transformer;
	}
	
	/**
	 * Checks if the given document starts with an XML Preamble {@code '<'}
	 * Processes values with or without BOM-encoding
	 * NOTE: does not check XML-conformity of the whole file
	 *       call isDOM(bytes) for a deep check
	 * 
	 * @param document {@link DSSDocument} to verify
	 * @return TRUE if the provided document starts from xmlPreamble, FALSE otherwise
	 */
	public static boolean startsWithXmlPreamble(DSSDocument document) {
		return DSSUtils.compareFirstBytes(document, xmlPreamble) || DSSUtils.compareFirstBytes(document, xmlWithBomPreample);
	}

	/**
	 * Creates the new empty Document.
	 *
	 * @return a new empty Document
	 */
	public static Document buildDOM() {
		try {
			return dbFactory.newDocumentBuilder().newDocument();
		} catch (ParserConfigurationException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on the XML string.
	 *
	 * @param xmlString
	 *            The string representing the dssDocument to be created.
	 * @return a new {@link org.w3c.dom.Document} with the xmlString content
	 */
	public static Document buildDOM(final String xmlString) {
		return buildDOM(xmlString.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on byte array.
	 *
	 * @param bytes
	 *            The bytes array representing the dssDocument to be created.
	 * @return a new {@link org.w3c.dom.Document} with the bytes content
	 */
	public static Document buildDOM(final byte[] bytes) {
		Objects.requireNonNull(bytes, "bytes is required");
		return buildDOM(new ByteArrayInputStream(bytes));
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on the {@link eu.europa.esig.dss.model.DSSDocument}.
	 *
	 * @param dssDocument
	 *            The DSS representation of the document from which the dssDocument is created.
	 * @return a new {@link org.w3c.dom.Document} from {@link eu.europa.esig.dss.model.DSSDocument}
	 */
	public static Document buildDOM(final DSSDocument dssDocument) {
		Objects.requireNonNull(dssDocument, "The document is null");
		return buildDOM(dssDocument.openStream());
	}

	/**
	 * This method returns true if the binaries contains a {@link org.w3c.dom.Document}
	 * 
	 * @param bytes
	 *            the binaries to be tested
	 * @return true if the binaries is a XML
	 */
	public static boolean isDOM(final byte[] bytes) {
		try {
			final Document dom = buildDOM(bytes);
			return dom != null;
		} catch (DSSException e) {
			// NOT DOM
			return false;
		}
	}

	/**
	 * This method returns true if the provided {@code InputStream} is a valid
	 * {@link org.w3c.dom.Document}
	 * 
	 * @param inputStream {@link InputStream} to be tested
	 * @return true if the document is an XML
	 */
	public static boolean isDOM(final InputStream inputStream) {
		try {
			final Document dom = buildDOM(inputStream);
			return dom != null;
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * This method returns true if the provided document is a valid XML
	 * {@link org.w3c.dom.Document}
	 * 
	 * @param dssDocument {@link DSSDocument} to be tested
	 * @return true if the document is an XML
	 */
	public static boolean isDOM(final DSSDocument dssDocument) {
		try {
			return startsWithXmlPreamble(dssDocument) && isDOM(dssDocument.openStream());
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on the XML
	 * inputStream.
	 *
	 * @param inputStream The inputStream stream representing the dssDocument to be
	 *                    created.
	 * @return a new {@link org.w3c.dom.Document} from {@link java.io.InputStream} @
	 */
	public static Document buildDOM(final InputStream inputStream) {
		try (InputStream is = inputStream) {
			return dbFactory.newDocumentBuilder().parse(is);
		} catch (Exception e) {
			throw new DSSException("Unable to parse content (XML expected)", e);
		}
	}

	/**
	 * This method adds an attribute with the namespace and the value
	 * 
	 * @param element
	 *            the element where the attribute is needed
	 * @param namespace
	 *            the used namespace for the attribute
	 * @param attribute
	 *            the attribute the be added
	 * @param value
	 *            the value for the given attribute
	 */
	public static void setAttributeNS(Element element, DSSNamespace namespace, DSSAttribute attribute, String value) {
		StringBuffer sb = new StringBuffer();
		sb.append(namespace.getPrefix());
		sb.append(':');
		sb.append(attribute.getAttributeName());

		element.setAttributeNS(namespace.getUri(), sb.toString(), value);
	}

	/**
	 * This method creates and adds a new XML {@code Element}
	 *
	 * @param document
	 *            root document
	 * @param parentDom
	 *            parent node
	 * @param namespace
	 *            namespace definition
	 * @param element
	 *            the type of element name
	 * @return added element
	 */
	public static Element addElement(final Document document, final Element parentDom, final DSSNamespace namespace, final DSSElement element) {
		final Element dom = createElementNS(document, namespace, element);
		parentDom.appendChild(dom);
		return dom;
	}

	
	/**
	 * This method creates a new instance of XPathExpression with the given xpath
	 * expression
	 * 
	 * @param xpathString
	 *                    XPath query string
	 * @return an instance of {@code XPathExpression} for the given xpathString @ if
	 */
	public static XPathExpression createXPathExpression(final String xpathString) {
		final XPath xpath = factory.newXPath();
		xpath.setNamespaceContext(namespacePrefixMapper);
		try {
			return xpath.compile(xpathString);
		} catch (XPathExpressionException ex) {
			throw new DSSException(ex);
		}
	}

	/**
	 * Returns the String value of the corresponding to the XPath query.
	 *
	 * @param xmlNode
	 *                    The node where the search should be performed.
	 * @param xPathString
	 *                    XPath query string
	 * @return string value of the XPath query
	 */
	public static String getValue(final Node xmlNode, final String xPathString) {
		try {
			final XPathExpression xPathExpression = createXPathExpression(xPathString);
			final String string = (String) xPathExpression.evaluate(xmlNode, XPathConstants.STRING);
			return Utils.trim(string);
		} catch (XPathExpressionException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Returns the NodeList corresponding to the XPath query.
	 *
	 * @param xmlNode
	 *                    The node where the search should be performed.
	 * @param xPathString
	 *                    XPath query string
	 * @return the NodeList corresponding to the XPath query
	 */
	public static NodeList getNodeList(final Node xmlNode, final String xPathString) {
		try {
			final XPathExpression expr = createXPathExpression(xPathString);
			return (NodeList) expr.evaluate(xmlNode, XPathConstants.NODESET);
		} catch (XPathExpressionException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Returns the Node corresponding to the XPath query.
	 *
	 * @param xmlNode
	 *            The node where the search should be performed.
	 * @param xPathString
	 *            XPath query string
	 * @return the Node corresponding to the XPath query.
	 */
	public static Node getNode(final Node xmlNode, final String xPathString) {
		final NodeList list = getNodeList(xmlNode, xPathString);
		if (list.getLength() > 1) {
			throw new DSSException("More than one result for XPath: " + xPathString);
		}
		return list.item(0);
	}

	/**
	 * Returns the Element corresponding to the XPath query.
	 *
	 * @param xmlNode
	 *            The node where the search should be performed.
	 * @param xPathString
	 *            XPath query string
	 * @return the Element corresponding to the XPath query
	 */
	public static Element getElement(final Node xmlNode, final String xPathString) {
		return (Element) getNode(xmlNode, xPathString);
	}

	/**
	 * Returns true if the xpath query contains something
	 *
	 * @param xmlNode
	 *            the current node
	 * @param xPathString
	 *            the expected child node
	 * @return true if the current node has any filled child node
	 */
	public static boolean isNotEmpty(final Node xmlNode, final String xPathString) {
		// xpath suffix allows to skip text nodes and empty lines
		NodeList nodeList = getNodeList(xmlNode, xPathString + "/child::node()[not(self::text())]");
		return (nodeList != null) && (nodeList.getLength() > 0);
	}

	/**
	 * This method creates and adds a new XML {@code Element} with text value
	 *
	 * @param document
	 *            root document
	 * @param parentDom
	 *            parent node
	 * @param namespace
	 *            namespace
	 * @param element
	 *            element type
	 * @param value
	 *            element text node value
	 * @return added element
	 */
	public static Element addTextElement(final Document document, final Element parentDom, final DSSNamespace namespace, final DSSElement element, final String value) {
		final Element dom = createElementNS(document, namespace, element);
		parentDom.appendChild(dom);
		final Text valueNode = document.createTextNode(value);
		dom.appendChild(valueNode);
		return dom;
	}

	/**
	 * This method sets a text node to the given DOM element.
	 *
	 * @param document
	 *            root document
	 * @param parentDom
	 *            parent node
	 * @param text
	 *            text to be added
	 */
	public static void setTextNode(final Document document, final Element parentDom, final String text) {
		final Text textNode = document.createTextNode(text);
		parentDom.appendChild(textNode);
	}

	/**
	 * Converts a given {@code Date} to a new {@code XMLGregorianCalendar}.
	 *
	 * @param date
	 *            the date to be converted
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
			return xmlGregorianCalendar.normalize(); // to UTC = Zulu
		} catch (DatatypeConfigurationException e) {
			LOG.warn("Unable to properly convert a Date to an XMLGregorianCalendar : {}", e.getMessage(), e);
		}
		return null;
	}

	/**
	 * This method allows to convert the given text (XML representation of a date) to the {@code Date}.
	 *
	 * @param text
	 *            the text representing the XML date
	 * @return {@code Date} converted or null
	 */
	public static Date getDate(final String text) {
		try {
			final DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
			final XMLGregorianCalendar xmlGregorianCalendar = datatypeFactory.newXMLGregorianCalendar(text);
			return xmlGregorianCalendar.toGregorianCalendar().getTime();
		} catch (Exception e) {
			LOG.warn("Unable to parse '{}'", text);
		}
		return null;
	}

	/**
	 * This method returns the list of children's names for a given {@code Node}.
	 *
	 * @param xmlNode
	 *            The node where the search should be performed.
	 * @param xPathString
	 *            XPath query string
	 * @return {@code List} of children's names
	 */
	public static List<String> getChildrenNames(final Node xmlNode, final String xPathString) {
		List<String> childrenNames = new ArrayList<>();
		final Element element = getElement(xmlNode, xPathString);
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
	 * This method writes the {@link org.w3c.dom.Document} content to an
	 * outputStream
	 * 
	 * @param dom
	 *            the {@link org.w3c.dom.Document} to be writed
	 * @param os
	 *            the OutputStream @ if any error occurred
	 */
	public static void writeDocumentTo(final Document dom, final OutputStream os) {
		try {
			final DOMSource xmlSource = new DOMSource(dom);
			final StreamResult outputTarget = new StreamResult(os);
			Transformer transformer = getSecureTransformer();
			transformer.transform(xmlSource, outputTarget);
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method creates a new InMemoryDocument with the {@link org.w3c.dom.Document} content and the given name
	 * 
	 * @param document
	 *            the {@link org.w3c.dom.Document} to store
	 * @param name
	 *            the ouput filename
	 * @return a new instance of InMemoryDocument with the XML and the given filename
	 */
	public static DSSDocument createDssDocumentFromDomDocument(Document document, String name) {
		try (ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
			DomUtils.writeDocumentTo(document, baos);
			return new InMemoryDocument(baos.toByteArray(), name, MimeType.XML);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method allows to convert an XML {@code Node} to a {@code String}.
	 *
	 * @param node
	 *            {@code Node} to be converted
	 * @return {@code String} representation of the node
	 */
	public static String xmlToString(final Node node) {
		try {
			final Source source = new DOMSource(node);
			final StringWriter stringWriter = new StringWriter();
			final Result result = new StreamResult(stringWriter);
			final Transformer transformer = getSecureTransformer();
			transformer.transform(source, result);
			return stringWriter.getBuffer().toString();
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method returns stored namespace definitions
	 * 
	 * @return a map with the prefix and the related URI
	 */
	public static Map<String, String> getCurrentNamespaces() {
		return namespacePrefixMapper.getPrefixMap();
	}

	/**
	 * Returns case-insensitive xPath expression
	 * @param uri to find
	 * @return {@link String} xPath expression
	 */
	public static String getXPathByIdAttribute(String uri) {
		String id = getId(uri);
		return "[@Id='" + id + "' or @id='" + id + "' or @ID='" + id + "']";
	}

	public static String getId(String uri) {
		String id = uri;
		if (startsFromHash(uri)) {
			id = id.substring(1);
		}
		return id;
	}

	/**
	 * Returns TRUE if the provided {@code uri} starts from the hash "#" character
	 * @param uri {@link String} to be checked
	 * @return TRUE if {@code uri} is starts from "#", FALSE otherwise
	 */
	public static boolean startsFromHash(String uri) {
		return Utils.isStringNotBlank(uri) && uri.startsWith("#");
	}
	
	/**
	 * Returns TRUE if the provided {@code uri} refers to an element in the signature
	 * @param uri {@link String} to be checked
	 * @return TRUE if {@code uri} is referred to an element, FALSE otherwise
	 */
	public static boolean isElementReference(String uri) {
		return startsFromHash(uri) && !isXPointerQuery(uri);
	}

	/**
	 * Indicates if the given URI is an XPointer query.
	 *
	 * @param uriValue
	 *            URI to be analysed
	 * @return true if it is an XPointer query
	 */
	public static boolean isXPointerQuery(String uriValue) {
		if (Utils.isStringEmpty(uriValue)) {
			return false;
		}
		String decodedUri = DSSUtils.decodeUrl(uriValue);
		if (decodedUri == null) {
			return false;
		}
		final String[] parts = getId(decodedUri).split("\\s");
		int ii = 0;
		for (; ii < parts.length - 1; ++ii) {
			if (!parts[ii].endsWith(")") || !parts[ii].startsWith(XNS_OPEN)) {
				return false;
			}
		}
		if (!parts[ii].endsWith(")") || !parts[ii].startsWith(XP_OPEN)) {
			return false;
		}
		return true;
	}
	
	/**
     * Method getXPointerId
     * See {@code org.apache.xml.security.utils.resolver.implementations.ResolverXPointer}
     *
     * @param uri {@link String}
     * @return xpointerId to search.
     */
    public static String getXPointerId(String uri) {
        if (uri.startsWith(XP_WITH_ID_OPEN) && uri.endsWith("))")) {
            String idPlusDelim = uri.substring(XP_WITH_ID_OPEN.length(), uri.length() - 2);

            int idLen = idPlusDelim.length() -1;
            if (idPlusDelim.charAt(0) == '"' && idPlusDelim.charAt(idLen) == '"'
                || idPlusDelim.charAt(0) == '\'' && idPlusDelim.charAt(idLen) == '\'') {
                return idPlusDelim.substring(1, idLen);
            }
        }

        return null;
    }

	/**
	 * Creates an element with the given namespace
	 *
	 * @param documentDom {@link Document} to add the element into
	 * @param namespace {@link DSSNamespace} namespace to be defined
	 * @param element {@link DSSElement} to add
	 * @return created {@link Element} with the namespace
	 */
	public static Element createElementNS(Document documentDom, DSSNamespace namespace, DSSElement element) {
		StringBuffer elementSB = new StringBuffer();
		if (Utils.isStringNotEmpty(namespace.getPrefix())) {
			elementSB.append(namespace.getPrefix());
			elementSB.append(':');
		}
		elementSB.append(element.getTagName());
		return documentDom.createElementNS(namespace.getUri(), elementSB.toString());
	}

	/**
	 * Adds a namespace attribute to the element
	 *
	 * @param element {@link Element} to add a namespace to
	 * @param namespace {@link DSSNamespace} to add
	 */
	public static void addNamespaceAttribute(Element element, DSSNamespace namespace) {
		StringBuffer namespaceAttribute = new StringBuffer();
		namespaceAttribute.append("xmlns:");
		namespaceAttribute.append(namespace.getPrefix());
		element.setAttribute(namespaceAttribute.toString(), namespace.getUri());
	}

	/**
	 * Returns a Node with excluded comments.
	 * 
	 * NOTE: the method modifies the original {@code node}!
	 * 
	 * @param node {@link Node} to process
	 * @return binaries of the {@code node} without comments
	 */
	public static Node excludeComments(Node node) {
		excludeCommentsRecursively(node);
		// workaround to handle the transforms correctly (clone does not work)
		// TODO: improve
		return buildDOM(xmlToString(node));
	}

	private static void excludeCommentsRecursively(final Node node) {
		NodeList childNodes = node.getChildNodes();
		for (int ii = 0; ii < childNodes.getLength(); ii++) {
			Node childNode = childNodes.item(ii);
			if (Node.COMMENT_NODE == childNode.getNodeType()) {
				node.removeChild(childNode);
			}
			if (childNode.hasChildNodes()) {
				excludeCommentsRecursively(childNode);
			}
		}
	}

}

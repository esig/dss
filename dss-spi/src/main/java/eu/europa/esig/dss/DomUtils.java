package eu.europa.esig.dss;

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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

public final class DomUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DomUtils.class);

	private DomUtils() {
	}

	private static DocumentBuilderFactory dbFactory;
	private static final XPathFactory factory = XPathFactory.newInstance();
	private static NamespaceContextMap namespacePrefixMapper;

	private static final Map<String, String> namespaces;

	static {
		namespacePrefixMapper = new NamespaceContextMap();
		namespaces = new HashMap<String, String>();
		registerDefaultNamespaces();

		dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		try {
			// disable external entities details :
			// https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet#Java

			dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
			dbFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
			dbFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
			dbFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);

			dbFactory.setXIncludeAware(false);
			dbFactory.setExpandEntityReferences(false);
		} catch (ParserConfigurationException e) {
			throw new DSSException("Unable to initialize the DocumentBuilderFactory", e);
		}
	}

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
	}

	/**
	 * This method allows to register a namespace and associated prefix. If the prefix exists already it is replaced.
	 *
	 * @param prefix
	 *            namespace prefix
	 * @param namespace
	 *            namespace
	 * @return true if this map did not already contain the specified element
	 */
	public static boolean registerNamespace(final String prefix, final String namespace) {
		final String put = namespaces.put(prefix, namespace);
		namespacePrefixMapper.registerNamespace(prefix, namespace);
		return put == null;
	}

	/**
	 * This method returns a new instance of TransformerFactory with secured features enabled
	 * 
	 * @return an instance of TransformerFactory with enabled secure features
	 */
	public static TransformerFactory getSecureTransformerFactory() {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		try {
			transformerFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
			transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
		} catch (TransformerConfigurationException e) {
			throw new DSSException(e);
		}
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
			transformer.setOutputProperty(OutputKeys.METHOD, "xml");
		} catch (TransformerConfigurationException e) {
			throw new DSSException(e);
		}
		transformer.setErrorListener(new DSSXmlErrorListener());
		return transformer;
	}

	/**
	 * Creates the new empty Document.
	 *
	 * @return a new empty Document
	 * 
	 * @throws DSSException
	 *             in case of exceptions while the document creation
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
	 * @throws DSSException
	 *             if the xmlString cannot be parsed
	 */
	public static Document buildDOM(final String xmlString) throws DSSException {
		return buildDOM(xmlString.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on byte array.
	 *
	 * @param bytes
	 *            The bytes array representing the dssDocument to be created.
	 * @return a new {@link org.w3c.dom.Document} with the bytes content
	 * @throws DSSException
	 *             if the bytes cannot be parsed
	 */
	public static Document buildDOM(final byte[] bytes) throws DSSException {
		return buildDOM(new ByteArrayInputStream(bytes));
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on the {@link eu.europa.esig.dss.DSSDocument}.
	 *
	 * @param dssDocument
	 *            The DSS representation of the document from which the dssDocument is created.
	 * @return a new {@link org.w3c.dom.Document} from {@link eu.europa.esig.dss.DSSDocument}
	 * @throws DSSException
	 *             if the {@link eu.europa.esig.dss.DSSDocument} cannot be parsed
	 */
	public static Document buildDOM(final DSSDocument dssDocument) throws DSSException {
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
	 * This method returns the {@link org.w3c.dom.Document} created based on the XML inputStream.
	 *
	 * @param inputStream
	 *            The inputStream stream representing the dssDocument to be created.
	 * @return a new {@link org.w3c.dom.Document} from {@link java.io.InputStream}
	 * @throws DSSException
	 *             if the {@link java.io.InputStream} cannot be parsed
	 */
	public static Document buildDOM(final InputStream inputStream) throws DSSException {
		try (InputStream is = inputStream) {
			final Document rootElement = dbFactory.newDocumentBuilder().parse(is);
			return rootElement;
		} catch (Exception e) {
			throw new DSSException("Unable to parse content (XML expected)", e);
		}
	}

	/**
	 * This method creates and adds a new XML {@code Element}
	 *
	 * @param document
	 *            root document
	 * @param parentDom
	 *            parent node
	 * @param namespace
	 *            namespace
	 * @param name
	 *            element name
	 * @return added element
	 */
	public static Element addElement(final Document document, final Element parentDom, final String namespace, final String name) {
		final Element dom = document.createElementNS(namespace, name);
		parentDom.appendChild(dom);
		return dom;
	}

	/**
	 * This method creates a new instance of XPathExpression with the given xpath expression
	 * 
	 * @param xpathString
	 *            XPath query string
	 * @return an instance of {@code XPathExpression} for the given xpathString
	 * @throws DSSException
	 *             if the xpath expression cannot be compiled
	 */
	private static XPathExpression createXPathExpression(final String xpathString) throws DSSException {
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
	 * Returns the String value of the corresponding to the XPath query.
	 *
	 * @param xmlNode
	 *            The node where the search should be performed.
	 * @param xPathString
	 *            XPath query string
	 * @return string value of the XPath query
	 * @throws DSSException
	 *             if the xpath expression cannot be compiled/evaluated
	 */
	public static String getValue(final Node xmlNode, final String xPathString) throws DSSException {
		try {
			final XPathExpression xPathExpression = createXPathExpression(xPathString);
			final String string = (String) xPathExpression.evaluate(xmlNode, XPathConstants.STRING);
			return string.trim();
		} catch (XPathExpressionException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Returns the NodeList corresponding to the XPath query.
	 *
	 * @param xmlNode
	 *            The node where the search should be performed.
	 * @param xPathString
	 *            XPath query string
	 * @return the NodeList corresponding to the XPath query
	 * @throws DSSException
	 *             if an error occurred
	 */
	public static NodeList getNodeList(final Node xmlNode, final String xPathString) throws DSSException {
		try {
			final XPathExpression expr = createXPathExpression(xPathString);
			final NodeList evaluated = (NodeList) expr.evaluate(xmlNode, XPathConstants.NODESET);
			return evaluated;
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
		if ((nodeList != null) && (nodeList.getLength() > 0)) {
			return true;
		}
		return false;
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
	 * @param name
	 *            element name
	 * @param value
	 *            element text node value
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
			xmlGregorianCalendar = xmlGregorianCalendar.normalize(); // to UTC = Zulu
			return xmlGregorianCalendar;
		} catch (DatatypeConfigurationException e) {
			LOG.warn("Unable to properly convert a Date to an XMLGregorianCalendar " + e.getMessage(), e);
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
		} catch (DatatypeConfigurationException e) {
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
		List<String> childrenNames = new ArrayList<String>();
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
	 * This method writes the {@link org.w3c.dom.Document} content to an outputStream
	 * 
	 * @param dom
	 *            the {@link org.w3c.dom.Document} to be writed
	 * @param os
	 *            the OutputStream
	 * @throws DSSException
	 *             if any error occurred
	 */
	public static void writeDocumentTo(final Document dom, final OutputStream os) throws DSSException {
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
		return new HashMap<String, String>(namespaces);
	}

	public static String getXPathByIdAttribute(String uri) {
		return "[@Id='" + getId(uri) + "']";
	}

	public static String getId(String uri) {
		String id = uri;
		if (uri.startsWith("#")) {
			id = id.substring(1);
		}
		return id;
	}

}

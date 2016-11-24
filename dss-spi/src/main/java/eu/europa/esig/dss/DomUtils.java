package eu.europa.esig.dss;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.OutputStream;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.DOMImplementation;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.esig.dss.utils.Utils;

public final class DomUtils {

	private DomUtils() {
	}

	private static DocumentBuilderFactory dbFactory;

	/**
	 * Guarantees that the xmlString builder has been created.
	 *
	 * @throws DSSException
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
		transformerFactory.setErrorListener(new DSSXmlErrorListener());
		return transformerFactory;
	}

	public static Transformer getSecureTransformer() {
		TransformerFactory transformerFactory = getSecureTransformerFactory();
		Transformer transformer = null;
		try {
			transformer = transformerFactory.newTransformer();
		} catch (TransformerConfigurationException e) {
			throw new DSSException(e);
		}
		transformer.setErrorListener(new DSSXmlErrorListener());
		return transformer;
	}

	/**
	 * Creates the new empty Document.
	 *
	 * @return
	 * @throws DSSException
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
	 * @param xmlString
	 *            The string representing the dssDocument to be created.
	 * @return
	 * @throws DSSException
	 */
	public static Document buildDOM(final String xmlString) throws DSSException {
		return buildDOM(DSSUtils.getUtf8Bytes(xmlString));
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on byte array.
	 *
	 * @param bytes
	 *            The bytes array representing the dssDocument to be created.
	 * @return
	 * @throws DSSException
	 */
	public static Document buildDOM(final byte[] bytes) throws DSSException {
		return buildDOM(new ByteArrayInputStream(bytes));
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on the {@link eu.europa.esig.dss.DSSDocument}.
	 *
	 * @param dssDocument
	 *            The DSS representation of the document from which the dssDocument is created.
	 * @return
	 * @throws DSSException
	 */
	public static Document buildDOM(final DSSDocument dssDocument) throws DSSException {
		return buildDOM(dssDocument.openStream());
	}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on the XML inputStream.
	 *
	 * @param inputStream
	 *            The inputStream stream representing the dssDocument to be created.
	 * @return
	 * @throws DSSException
	 */
	public static Document buildDOM(final InputStream inputStream) throws DSSException {
		try {
			ensureDocumentBuilder();
			final Document rootElement = dbFactory.newDocumentBuilder().parse(inputStream);
			return rootElement;
		} catch (Exception e) {
			throw new DSSException(e);
		} finally {
			Utils.closeQuietly(inputStream);
		}
	}

	/**
	 * Creates a DOM document without document element.
	 *
	 * @param namespaceURI
	 *            the namespace URI of the document element to create or null
	 * @param qualifiedName
	 *            the qualified name of the document element to be created or null
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

}

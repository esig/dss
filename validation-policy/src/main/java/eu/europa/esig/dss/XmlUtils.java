package eu.europa.esig.dss;

import java.io.InputStream;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;

public final class XmlUtils {

	private static DocumentBuilderFactory dbFactory;

	private XmlUtils() {}

	/**
	 * This method returns the {@link org.w3c.dom.Document} created based on the XML inputStream.
	 *
	 * @param inputStream The inputStream stream representing the dssDocument to be created.
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
}

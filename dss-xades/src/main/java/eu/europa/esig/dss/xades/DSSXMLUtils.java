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
import java.io.InputStream;
import java.util.HashSet;
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

import org.apache.xml.security.Init;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.transforms.Transforms;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.ResourceLoader;
import eu.europa.esig.dss.utils.Utils;

/**
 * Utility class that contains some XML related method.
 *
 */
public final class DSSXMLUtils {

	private static final Logger LOG = LoggerFactory.getLogger(DSSXMLUtils.class);

	public static final String ID_ATTRIBUTE_NAME = "id";
	public static final String XAD_ESV141_XSD = "/XAdESv141.xsd";

	private static final Set<String> transforms;

	private static final Set<String> canonicalizers;

	static {

		Init.init();

		transforms = new HashSet<String>();
		registerDefaultTransforms();

		canonicalizers = new HashSet<String>();
		registerDefaultCanonicalizers();
	}

	private static Schema schema = null;

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
	 * This method is used to serialize a given node
	 *
	 * @param xmlNode
	 *            The node to be serialized.
	 * @return
	 */
	public static byte[] serializeNode(final Node xmlNode) {
		try {
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

			ByteArrayOutputStream bos = new ByteArrayOutputStream();
			StreamResult result = new StreamResult(bos);
			Source source = new DOMSource(xmlNode);
			transformer.transform(source, result);
			return bos.toByteArray();
		} catch (Exception e) {
			throw new DSSException(e);
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

		if (transforms.contains(canonicalizationMethod)) {
			return false;
		}
		final boolean contains = canonicalizers.contains(canonicalizationMethod);
		return contains;
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
			throw new DSSException(e);
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
			final byte[] canonicalized = c14n.canonicalizeSubtree(node);
			return canonicalized;
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	/**
	 * An ID attribute can only be dereferenced if it is declared in the validation context. This behaviour is caused by
	 * the fact that the attribute does not have attached type of
	 * information. Another solution is to parse the XML against some DTD or XML schema. This process adds the necessary
	 * type of information to each ID attribute.
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
	 * If this method finds an attribute with names ID (case-insensitive) then it is returned. If there is more than one
	 * ID attributes then the first one is returned.
	 *
	 * @param element
	 *            to be checked
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
	 * If this method finds an attribute with names ID (case-insensitive) then declares it to be a user-determined ID
	 * attribute.
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
	 * This method allows to validate an XML against the XAdES XSD schema.
	 *
	 * @param streamSource
	 *            {@code InputStream} XML to validate
	 * @return null if the XSD validates the XML, error message otherwise
	 */
	public static String validateAgainstXSD(final StreamSource streamSource) {
		try {
			if (schema == null) {
				schema = getSchema();
			}
			final Validator validator = schema.newValidator();
			validator.validate(streamSource);
			return Utils.EMPTY_STRING;
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

}

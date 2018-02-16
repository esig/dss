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
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.xml.XMLConstants;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.datatype.XMLGregorianCalendar;
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
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuerSerial;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.MimeType;
import eu.europa.esig.dss.ResourceLoader;
import eu.europa.esig.dss.SignatureAlgorithm;
import eu.europa.esig.dss.XAdESNamespaces;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.xades.signature.XAdESBuilder;
import eu.europa.esig.dss.xades.signature.XAdESSignatureBuilder;

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

	public static boolean isOid(String policyId) {
		return policyId != null && policyId.matches("^(?i)urn:oid:.*$");
	}

	/**
	 * Create a XAdES object containing signature certificate, signing time and information about signed object.
	 *
	 * @param signingDate
	 *            Date to set as signing time
	 * @param signingCertificate
	 *            Signing certificate to incorporate into object
	 * @param signatureAlgorithm
	 *            Signature algorithm to incorporate into object
	 * @param signedObjectReferenceId
	 *            Reference ID to use for signed object within the DataObjectFormat element.
	 * @param signedObjectMimeType
	 *            Mimetype to use of signed object within the DataObjectFormat element
	 * @return Document representing a XAdES object based on given parameters
	 */
	public static Document createXAdESObject(final Date signingDate, final CertificateToken signingCertificate, final SignatureAlgorithm signatureAlgorithm,
			final String signedObjectReferenceId, final MimeType signedObjectMimeType) {
		Document signedPropertiesDocument;

		try {
			String deterministicId = DSSUtils.getDeterministicId(signingDate, signingCertificate.getDSSId());
			signedPropertiesDocument = DomUtils.buildDOM();
			Element objectElement = signedPropertiesDocument.createElementNS(XMLSignature.XMLNS, XAdESBuilder.DS_OBJECT);
			signedPropertiesDocument.appendChild(objectElement);

			Element qualifyingProperties = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_QUALIFYING_PROPERTIES);
			qualifyingProperties.setAttribute(XAdESBuilder.TARGET, "#" + deterministicId);
			objectElement.appendChild(qualifyingProperties);

			Element signedPropertiesElement = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_SIGNED_PROPERTIES);
			signedPropertiesElement.setAttribute(XAdESBuilder.ID, "xades-" + deterministicId);
			qualifyingProperties.appendChild(signedPropertiesElement);

			Element signedSignaturePropertiesElement = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132,
					XAdESBuilder.XADES_SIGNED_SIGNATURE_PROPERTIES);
			signedPropertiesElement.appendChild(signedSignaturePropertiesElement);
			Element signingTimeElement = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_SIGNING_TIME);
			final XMLGregorianCalendar xmlGregorianCalendar = DomUtils.createXMLGregorianCalendar(signingDate);
			final String xmlSigningTime = xmlGregorianCalendar.toXMLFormat();
			signingTimeElement.appendChild(signedPropertiesDocument.createTextNode(xmlSigningTime));
			signedSignaturePropertiesElement.appendChild(signingTimeElement);

			Element signingCertificateV2Element = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, "xades:SigningCertificateV2");
			Element certElement = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_CERT);
			Element certDigestElement = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_CERT_DIGEST);
			Element digestMethodElement = signedPropertiesDocument.createElementNS(XMLSignature.XMLNS, XAdESBuilder.DS_DIGEST_METHOD);
			digestMethodElement.setAttribute(XAdESBuilder.ALGORITHM, signatureAlgorithm.getXMLId());
			certDigestElement.appendChild(digestMethodElement);
			Element digestValueElement = signedPropertiesDocument.createElementNS(XMLSignature.XMLNS, XAdESBuilder.DS_DIGEST_VALUE);
			byte[] certDigestValue = signingCertificate.getDigest(signatureAlgorithm.getDigestAlgorithm());
			digestValueElement.appendChild(signedPropertiesDocument.createTextNode(new String(Base64.encode(certDigestValue))));
			certDigestElement.appendChild(digestValueElement);
			certElement.appendChild(certDigestElement);
			Element issuerSerialV2Element = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_ISSUER_SERIAL_V2);
			X500Name issuerX500Name = new X509CertificateHolder(signingCertificate.getEncoded()).getIssuer();
			GeneralName generalName = new GeneralName(issuerX500Name);
			GeneralNames generalNames = new GeneralNames(generalName);
			BigInteger serialNumber = signingCertificate.getSerialNumber();
			IssuerSerial issuerSerial = new IssuerSerial(generalNames, new ASN1Integer(serialNumber));
			issuerSerialV2Element.appendChild(
					signedPropertiesDocument.createTextNode(new String(Base64.encode(issuerSerial.toASN1Primitive().getEncoded(ASN1Encoding.DER)))));
			certElement.appendChild(issuerSerialV2Element);
			signingCertificateV2Element.appendChild(certElement);
			signedSignaturePropertiesElement.appendChild(signingCertificateV2Element);

			Element signedDataObjectProperties = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132,
					XAdESBuilder.XADES_SIGNED_DATA_OBJECT_PROPERTIES);
			Element dataObjectFormatElement = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_DATA_OBJECT_FORMAT);
			dataObjectFormatElement.setAttribute(XAdESSignatureBuilder.OBJECT_REFERENCE, "#" + signedObjectReferenceId);
			Element mimeTypeElement = signedPropertiesDocument.createElementNS(XAdESNamespaces.XAdES132, XAdESBuilder.XADES_MIME_TYPE);
			mimeTypeElement.appendChild(signedPropertiesDocument.createTextNode(signedObjectMimeType.getMimeTypeString()));
			dataObjectFormatElement.appendChild(mimeTypeElement);
			signedDataObjectProperties.appendChild(dataObjectFormatElement);
			signedPropertiesElement.appendChild(signedDataObjectProperties);
		} catch (Exception e) {
			LOG.error("Could not create XAdES object", e);
			throw new DSSException(e);
		}

		return signedPropertiesDocument;
	}

	/**
	 * Calculate digest value of DOM element
	 *
	 * @param element
	 *            DOM Element to calculate digest value for
	 * @param canonicalizationMethod
	 *            Canoncalization method to use
	 * @param digestAlgorithm
	 *            Digest algorithm to use
	 * @return Digest value for element based on given parameters
	 */
	public static byte[] calculateDigestValue(final Element element, final String canonicalizationMethod, final DigestAlgorithm digestAlgorithm) {
		byte[] digestValue;
		try {
			byte[] canonicalizedElement = canonicalizeSubtree(canonicalizationMethod, element);
			MessageDigest messageDigest = MessageDigest.getInstance(digestAlgorithm.getJavaName());
			digestValue = messageDigest.digest(canonicalizedElement);
		} catch (Exception e) {
			LOG.error("Could not calculate digest value", e);
			throw new DSSException(e);
		}
		return digestValue;
	}

	/**
	 * Get reference element for signed properties (Type equals 'http://uri.etsi.org/01903#SignedProperties')
	 *
	 * @param parentDocument
	 *            Document containing reference
	 * @return Element for reference to signed properties, or null if reference could not be found.
	 */
	public static Element getSignedPropertiesReferenceElement(final Document parentDocument) {
		NodeList references = parentDocument.getElementsByTagNameNS(XMLSignature.XMLNS, "Reference");
		for (int i = 0; i < references.getLength(); i++) {
			Element referenceCandidate = ((Element) references.item(i));
			String referenceType = referenceCandidate.getAttribute(XAdESBuilder.TYPE);
			if (referenceType != null && referenceType.equalsIgnoreCase("http://uri.etsi.org/01903#SignedProperties")) {
				return referenceCandidate;
			}
		}
		return null;
	}

	/**
	 * Update URI attribute value of a reference element.
	 *
	 * @param referenceElement
	 *            Reference element to update
	 * @param newURI
	 *            New value for URI attribute
	 * @return Updated reference, or null if element was null or not a reference
	 */
	public static Element updateReferenceURI(Element referenceElement, final String newURI) {
		if (referenceElement != null && referenceElement.getTagName().equalsIgnoreCase(XAdESBuilder.DS_REFERENCE)) {
			referenceElement.setAttribute(XAdESBuilder.URI, newURI);
			return referenceElement;
		}
		return null;
	}

	/**
	 * Update digest value of a reference element
	 *
	 * @param referenceElement
	 *            Reference element to update
	 * @param newDigestValue
	 *            New digest value
	 * @return Updated reference, or null if element was null or not a reference
	 */
	public static Element updateReferenceDigestValue(Element referenceElement, final byte[] newDigestValue) {
		try {
			if (referenceElement != null && referenceElement.getTagName().equalsIgnoreCase(XAdESBuilder.DS_REFERENCE)) {
				Element element = (Element) referenceElement.getElementsByTagNameNS(XMLSignature.XMLNS, "DigestValue").item(0);
				element.getFirstChild().setNodeValue(new String(Base64.encode(newDigestValue), "UTF-8"));
				return referenceElement;
			}
		} catch (Exception e) {
			LOG.error("Could not update reference digest value", e);
		}
		return null;
	}
}

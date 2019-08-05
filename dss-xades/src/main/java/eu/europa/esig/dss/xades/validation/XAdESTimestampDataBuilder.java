package eu.europa.esig.dss.xades.validation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.ArchiveTimestampType;
import eu.europa.esig.dss.validation.timestamp.TimestampDataBuilder;
import eu.europa.esig.dss.validation.timestamp.TimestampInclude;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.XAdESUtils;
import eu.europa.esig.dss.xades.XPathQueryHolder;

public class XAdESTimestampDataBuilder implements TimestampDataBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESTimestampDataBuilder.class);
	
	private final List<Reference> references;
	private final Element signature;
	private final XPathQueryHolder xPathQueryHolder;
	
	public XAdESTimestampDataBuilder(final Element signature, final List<Reference> references, final XPathQueryHolder xPathQueryHolder) {
		this.signature = signature;
		this.references = references;
		this.xPathQueryHolder = xPathQueryHolder;
	}

	@Override
	public byte[] getContentTimestampData(final TimestampToken timestampToken) {
		final TimestampType timeStampType = timestampToken.getTimeStampType();
		if (!TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP.equals(timeStampType) && !TimestampType.ALL_DATA_OBJECTS_TIMESTAMP.equals(timeStampType)) {
			return null;
		}

		if (!checkTimestampTokenIncludes(timestampToken)) {
			throw new DSSException("The Included referencedData attribute is either not present or set to false!");
		}
		if (references.isEmpty()) {
			throw new DSSException("The method 'checkSignatureIntegrity' must be invoked first!");
		}

		final String canonicalizationMethod = timestampToken.getCanonicalizationMethod();
		final List<TimestampInclude> includes = timestampToken.getTimestampIncludes();

		try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
			for (final Reference reference : references) {
				if (isContentTimestampedReference(reference, timeStampType, includes)) {
					byte[] referenceBytes = getReferenceBytes(reference, canonicalizationMethod);
					outputStream.write(referenceBytes);
				}
			}
			byte[] byteArray = outputStream.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("IndividualDataObjectsTimestampData/AllDataObjectsTimestampData bytes: {}", new String(byteArray));
			}
			return byteArray;
		} catch (IOException | XMLSecurityException e) {
			LOG.warn("Unable to extract IndividualDataObjectsTimestampData/AllDataObjectsTimestampData", e);
		}
		return null;

	}
	
	private byte[] getReferenceBytes(final Reference reference, final String canonicalizationMethod) throws XMLSecurityException {
		byte[] referencedBytes = reference.getReferencedBytes();
		if (Utils.isStringNotBlank(canonicalizationMethod) && DomUtils.isDOM(referencedBytes)) {
			referencedBytes = DSSXMLUtils.canonicalize(canonicalizationMethod, referencedBytes);
		}
		if (LOG.isTraceEnabled()) {
			LOG.trace("ReferencedBytes : {}", new String(referencedBytes));
		}
		return referencedBytes;
	}

	/**
	 * This method ensures that all Include elements referring to the Reference elements have a referencedData
	 * attribute, which is set to "true". In case one of
	 * these Include elements has its referenceData set to false, the method returns false
	 *
	 * @param timestampToken
	 * @return
	 */
	private boolean checkTimestampTokenIncludes(final TimestampToken timestampToken) {
		final List<TimestampInclude> timestampIncludes = timestampToken.getTimestampIncludes();
		if (Utils.isCollectionNotEmpty(timestampIncludes)) {
			for (final TimestampInclude timestampInclude : timestampIncludes) {
				if (!timestampInclude.isReferencedData()) {
					return false;
				}
			}
		}
		return true;
	}

	private boolean isContentTimestampedReference(Reference reference, TimestampType timeStampType, List<TimestampInclude> includes) {
		if (TimestampType.ALL_DATA_OBJECTS_TIMESTAMP.equals(timeStampType)) {
			// All references are covered except the one referencing the SignedProperties
			return !XAdESUtils.isSignedProperties(reference, new XPathQueryHolder());
		} else {
			for (TimestampInclude timestampInclude : includes) {
				String id = timestampInclude.getURI();
				if (reference.getId().equals(id)) {
					return true;
				}
			}
			return false;
		}
	}

	@Override
	public byte[] getSignatureTimestampData(final TimestampToken timestampToken) {
		return getSignatureTimestampData(timestampToken, null);
	}
	
	/**
	 * Returns SignatureTimestamp Data for a new Timestamp
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @return timestamp data
	 */
	public byte[] getSignatureTimestampData(final String canonicalizationMethod) {
		return getSignatureTimestampData(null, canonicalizationMethod);
	}

	protected byte[] getSignatureTimestampData(final TimestampToken timestampToken, String canonicalizationMethod) {
		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;
		try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
			writeCanonicalizedValue(xPathQueryHolder.XPATH_SIGNATURE_VALUE, canonicalizationMethod, buffer);
			final byte[] byteArray = buffer.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("Signature timestamp canonicalized string : \n{}", new String(byteArray));
			}
			return byteArray;
		} catch (IOException e) {
			throw new DSSException("Error when computing the SignatureTimestamp", e);
		}
	}

	@Override
	public byte[] getTimestampX1Data(final TimestampToken timestampToken) {
		return getTimestampX1Data(timestampToken, null);
	}
	
	/**
	 * Returns SigAndRefsTimestamp Data for a new Timestamp
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @return timestamp data
	 */
	public byte[] getTimestampX1Data(final String canonicalizationMethod) {
		return getTimestampX1Data(null, canonicalizationMethod);
	}

	protected byte[] getTimestampX1Data(final TimestampToken timestampToken, String canonicalizationMethod) {
		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;
		try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
			writeCanonicalizedValue(xPathQueryHolder.XPATH_SIGNATURE_VALUE, canonicalizationMethod, buffer);
			final NodeList signatureTimeStampNode = DomUtils.getNodeList(signature, xPathQueryHolder.XPATH_SIGNATURE_TIMESTAMP);
			if (signatureTimeStampNode != null) {
				for (int ii = 0; ii < signatureTimeStampNode.getLength(); ii++) {
					final Node item = signatureTimeStampNode.item(ii);
					final byte[] canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, item);
					buffer.write(canonicalizedValue);
				}
			}
			writeCanonicalizedValue(xPathQueryHolder.XPATH_COMPLETE_CERTIFICATE_REFS, canonicalizationMethod, buffer);
			writeCanonicalizedValue(xPathQueryHolder.XPATH_COMPLETE_REVOCATION_REFS, canonicalizationMethod, buffer);
			final byte[] byteArray = buffer.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("X1Timestamp (SigAndRefsTimeStamp) canonicalised string : \n{}", new String(byteArray));
			}
			return byteArray;
		} catch (IOException e) {
			throw new DSSException("Error when computing the SigAndRefsTimeStamp (X1Timestamp)", e);
		}
	}

	@Override
	public byte[] getTimestampX2Data(final TimestampToken timestampToken) {
		return getTimestampX2Data(timestampToken, null);
	}
	
	/**
	 * Returns RefsOnlyTimestamp Data for a new Timestamp
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @return timestamp data
	 */
	public byte[] getTimestampX2Data(final String canonicalizationMethod) {
		return getTimestampX2Data(null, canonicalizationMethod);
	}

	protected byte[] getTimestampX2Data(final TimestampToken timestampToken, String canonicalizationMethod) {
		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;
		try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
			writeCanonicalizedValue(xPathQueryHolder.XPATH_COMPLETE_CERTIFICATE_REFS, canonicalizationMethod, buffer);
			writeCanonicalizedValue(xPathQueryHolder.XPATH_COMPLETE_REVOCATION_REFS, canonicalizationMethod, buffer);

			final byte[] byteArray = buffer.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("TimestampX2Data (RefsOnlyTimeStamp) canonicalised string : \n{}", new String(byteArray));
			}
			return byteArray;
		} catch (IOException e) {
			throw new DSSException("Error when computing the RefsOnlyTimeStamp (TimestampX2D)", e);
		}
	}
	
	@Override
	public byte[] getArchiveTimestampData(final TimestampToken timestampToken) {
		return getArchiveTimestampData(timestampToken, null);
	}
	
	/**
	 * Returns ArchiveTimestamp Data for a new Timestamp
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @return timestamp data
	 */
	public byte[] getArchiveTimestampData(final String canonicalizationMethod) {
		return getArchiveTimestampData(null, canonicalizationMethod);
	}

	/**
	 * Gathers the data to be used to calculate the hash value sent to the TSA (messageImprint).
	 *
	 * @param timestampToken
	 *            {@code TimestampToken} to validate, or {@code null} when adding a new archive timestamp
	 * @param canonicalizationMethod
	 * @return {@code byte} array containing the canonicalized and concatenated timestamped data
	 */
	protected byte[] getArchiveTimestampData(final TimestampToken timestampToken, String canonicalizationMethod) {

		if (LOG.isTraceEnabled()) {
			LOG.trace("--->Get archive timestamp data : {}", (timestampToken == null ? "--> CREATION" : "--> VALIDATION"));
		}
		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;
		/**
		 * 8.2.1 Not distributed case<br>
		 *
		 * When xadesv141:ArchiveTimeStamp and all the unsigned properties covered by its time-stamp certificateToken
		 * have the same parent, this property uses
		 * the Implicit mechanism for all the time-stamped data objects. The input to the computation of the digest
		 * value MUST be built as follows:
		 * 
		 * 1) Initialize the final octet stream as an empty octet stream.
		 */
		try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {

			/**
			 * 2) Take all the ds:Reference elements in their order of appearance within ds:SignedInfo referencing
			 * whatever the signer wants to sign including
			 * the SignedProperties element. Process each one as indicated below:<br>
			 * - Process the retrieved ds:Reference element according to the reference processing model of XMLDSIG.<br>
			 * - If the result is a XML node set, canonicalize it. If ds:Canonicalization is present, the algorithm
			 * indicated by this element is used. If not,
			 * the standard canonicalization method specified by XMLDSIG is used.<br>
			 * - Concatenate the resulting octets to the final octet stream.
			 */

			/**
			 * The references are already calculated {@see #checkSignatureIntegrity()}
			 */
			final Set<String> referenceURIs = new HashSet<String>();
			for (final Reference reference : references) {
				referenceURIs.add(DomUtils.getId(reference.getURI()));
				writeReferenceBytes(reference, buffer);
			}

			/**
			 * 3) Take the following XMLDSIG elements in the order they are listed below, canonicalize each one and
			 * concatenate each resulting octet stream to
			 * the final octet stream:<br>
			 * - The ds:SignedInfo element.<br>
			 * - The ds:SignatureValue element.<br>
			 * - The ds:KeyInfo element, if present.
			 */
			writeCanonicalizedValue(xPathQueryHolder.XPATH_SIGNED_INFO, canonicalizationMethod, buffer);
			writeCanonicalizedValue(xPathQueryHolder.XPATH_SIGNATURE_VALUE, canonicalizationMethod, buffer);
			writeCanonicalizedValue(xPathQueryHolder.XPATH_KEY_INFO, canonicalizationMethod, buffer);
			/**
			 * 4) Take the unsigned signature properties that appear before the current xadesv141:ArchiveTimeStamp in
			 * the order they appear within the
			 * xades:UnsignedSignatureProperties, canonicalize each one and concatenate each resulting octet stream to
			 * the final octet stream. While
			 * concatenating the following rules apply:
			 */
			final Element unsignedSignaturePropertiesDom = getUnsignedSignaturePropertiesDom();
			if (unsignedSignaturePropertiesDom == null) {
				throw new NullPointerException(xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
			}
			writeTimestampedUnsignedProperties(unsignedSignaturePropertiesDom, timestampToken, canonicalizationMethod, buffer);
			
			/**
			 * 5) Take all the ds:Object elements except the one containing xades:QualifyingProperties element.
			 * Canonicalize each one and concatenate each resulting octet stream to the final octet stream. 
			 * If ds:Canonicalization is present, the algorithm indicated by this element is used. If not, 
			 * the standard canonicalization method specified by XMLDSIG is used.
			 */
			boolean xades141 = (timestampToken == null) || !ArchiveTimestampType.XAdES.equals(timestampToken.getArchiveTimestampType());
			final NodeList objects = getObjects();
			writeObjectBytes(objects, referenceURIs, canonicalizationMethod, xades141, buffer);
			
			byte[] bytes = buffer.toByteArray();
			if(LOG.isTraceEnabled()) {
				LOG.trace("Data to TimeStamp:");
				LOG.trace(new String(bytes));
			}
			return bytes;
			
		} catch (IOException e) {
			throw new DSSException("Error when computing the archive data", e);
		}
	}
	
	private void writeReferenceBytes(final Reference reference, ByteArrayOutputStream buffer) throws IOException {
		try {
			final byte[] referencedBytes = reference.getReferencedBytes();
			if (referencedBytes != null) {
				buffer.write(referencedBytes);
			} else {
				LOG.warn("No binaries found for URI '{}'", reference.getURI());
			}
		} catch (XMLSecurityException e) {
			LOG.warn("Unable to retrieve content for URI '{}' : {}", reference.getURI(), e.getMessage());
		}
	}

	private void writeCanonicalizedValue(final String xPathString, final String canonicalizationMethod, final ByteArrayOutputStream buffer) throws IOException {
		final Element element = DomUtils.getElement(signature, xPathString);
		if (element != null) {
			buffer.write(DSSXMLUtils.canonicalizeOrSerializeSubtree(canonicalizationMethod, element));
		}
	}

	private Element getUnsignedSignaturePropertiesDom() {
		return DomUtils.getElement(signature, xPathQueryHolder.XPATH_UNSIGNED_SIGNATURE_PROPERTIES);
	}
	
	private void writeTimestampedUnsignedProperties(final Element unsignedSignaturePropertiesDom, TimestampToken timestampToken, 
			String canonicalizationMethod, ByteArrayOutputStream buffer) throws IOException {
		
		final NodeList unsignedProperties = unsignedSignaturePropertiesDom.getChildNodes();
		for (int ii = 0; ii < unsignedProperties.getLength(); ii++) {

			final Node node = unsignedProperties.item(ii);
			if (node.getNodeType() != Node.ELEMENT_NODE) {
				// This can happened when there is a blank line between tags.
				continue;
			}
			final String localName = node.getLocalName();
			// In the SD-DSS implementation when validating the signature
			// the framework will not add missing data. To do so the
			// signature must be extended.
			// if (localName.equals("CertificateValues")) {
			/*
			 * - The xades:CertificateValues property MUST be added if it is not already present and the ds:KeyInfo
			 * element does not contain the full set of
			 * certificates used to validate the electronic signature.
			 */
			// } else if (localName.equals("RevocationValues")) {
			/*
			 * - The xades:RevocationValues property MUST be added if it is not already present and the ds:KeyInfo
			 * element does not contain the revocation
			 * information that has to be shipped with the electronic signature
			 */
			// } else if (localName.equals("AttrAuthoritiesCertValues")) {
			/*
			 * - The xades:AttrAuthoritiesCertValues property MUST be added if not already present and the following
			 * conditions are true: there exist an
			 * attribute certificate in the signature AND a number of certificates that have been used in its
			 * validation do not appear in CertificateValues.
			 * Its content will satisfy with the rules specified in clause 7.6.3.
			 */
			// } else if (localName.equals("AttributeRevocationValues")) {
			/*
			 * - The xades:AttributeRevocationValues property MUST be added if not already present and there the
			 * following conditions are true: there exist
			 * an attribute certificate AND some revocation data that have been used in its validation do not appear
			 * in RevocationValues. Its content will
			 * satisfy with the rules specified in clause 7.6.4.
			 */
			// } else
			if (XPathQueryHolder.XMLE_ARCHIVE_TIME_STAMP.equals(localName)) {
				// TODO: compare encoded base64
				if ((timestampToken != null) && (timestampToken.getHashCode() == node.hashCode())) {
					break;
				}
				
			} else if ("TimeStampValidationData".equals(localName)) {
				/**
				 * ETSI TS 101 903 V1.4.2 (2010-12) 8.1 The new XAdESv141:TimeStampValidationData element ../.. This
				 * element is specified to serve as an
				 * optional container for validation data required for carrying a full verification of time-stamp
				 * tokens embedded within any of the
				 * different time-stamp containers defined in the present document. ../.. 8.1.1 Use of URI attribute
				 * ../.. a new
				 * xadesv141:TimeStampValidationData element SHALL be created containing the missing validation data
				 * information and it SHALL be added as a
				 * child of UnsignedSignatureProperties elements immediately after the respective time-stamp
				 * certificateToken container element.
				 */
			}
			
			byte[] canonicalizedValue;
			if (timestampToken == null) { // Creation of the timestamp
				/**
				 * This is the work around for the name space problem: The issue was reported on:
				 * https://issues.apache.org/jira/browse/SANTUARIO-139 and
				 * considered as close. But for me (Bob) it still does not work!
				 */
				final byte[] bytesToCanonicalize = DSSXMLUtils.serializeNode(node);
				canonicalizedValue = DSSXMLUtils.canonicalize(canonicalizationMethod, bytesToCanonicalize);
			} else {
				canonicalizedValue = DSSXMLUtils.canonicalizeOrSerializeSubtree(canonicalizationMethod, node);
			}
			if (LOG.isTraceEnabled()) {
				LOG.trace("{}: Canonicalization: {} : \n{}", localName, canonicalizationMethod,
						new String(canonicalizedValue));
			}
			buffer.write(canonicalizedValue);
		}
	}

	/**
	 * This method returns the list of ds:Object elements for the current signature element.
	 *
	 * @return
	 */
	private NodeList getObjects() {
		return DomUtils.getNodeList(signature, XPathQueryHolder.XPATH_OBJECT);
	}
	
	private void writeObjectBytes(final NodeList objects, final Set<String> referenceURIs, String canonicalizationMethod, boolean xades141,
			ByteArrayOutputStream buffer) throws IOException {
		for (int ii = 0; ii < objects.getLength(); ii++) {

			final Node node = objects.item(ii);
			final Node qualifyingProperties = DomUtils.getElement(node, xPathQueryHolder.XPATH__QUALIFYING_PROPERTIES);
			if (qualifyingProperties != null) {
				continue;
			}
			if (!xades141) {
				/**
				 * !!! ETSI TS 101 903 V1.3.2 (2006-03) 5) Take any ds:Object element in the signature that is not
				 * referenced by any ds:Reference within
				 * ds:SignedInfo, except that one containing the QualifyingProperties element. Canonicalize each one
				 * and concatenate each resulting octet
				 * stream to the final octet stream. If ds:Canonicalization is present, the algorithm indicated by
				 * this element is used. If not, the
				 * standard canonicalization method specified by XMLDSIG is used.
				 */
				final NamedNodeMap attributes = node.getAttributes();
				final int length = attributes.getLength();
				String id = "";
				for (int jj = 0; jj < length; jj++) {
					final Node item = attributes.item(jj);
					final String nodeName = item.getNodeName();
					if (Utils.areStringsEqualIgnoreCase("ID", nodeName)) {
						id = item.getNodeValue();
						break;
					}
				}
				final boolean contains = referenceURIs.contains(id);
				if (contains) {
					continue;
				}
			}
			byte[] canonicalizedValue = DSSXMLUtils.canonicalizeOrSerializeSubtree(canonicalizationMethod, node);
			buffer.write(canonicalizedValue);
		}
		
	}

}

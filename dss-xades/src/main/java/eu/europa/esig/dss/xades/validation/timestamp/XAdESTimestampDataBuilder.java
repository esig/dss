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
package eu.europa.esig.dss.xades.validation.timestamp;

import eu.europa.esig.dss.DomUtils;
import eu.europa.esig.dss.definition.DSSElement;
import eu.europa.esig.dss.definition.xmldsig.XMLDSigPaths;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.timestamp.TimestampDataBuilder;
import eu.europa.esig.dss.validation.timestamp.TimestampInclude;
import eu.europa.esig.dss.validation.timestamp.TimestampToken;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.dss.xades.definition.XAdESPaths;
import eu.europa.esig.dss.xades.definition.xades132.XAdES132Element;
import eu.europa.esig.dss.xades.definition.xades141.XAdES141Element;
import eu.europa.esig.dss.xades.reference.ReferenceOutputType;
import eu.europa.esig.dss.xades.validation.XAdESAttribute;
import eu.europa.esig.dss.xades.validation.XAdESUnsignedSigProperties;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Builds a message-imprint for XAdES timestamps
 */
public class XAdESTimestampDataBuilder implements TimestampDataBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESTimestampDataBuilder.class);

	/** List of XAdES signature references */
	private final List<Reference> references;

	/** The signature element */
	private final Element signature;

	/** The XAdES XPaths to use */
	private final XAdESPaths xadesPaths;

	/**
	 * Default constructor
	 *
	 * @param signature {@link Element} the signature element
	 * @param references a list of found {@link Reference}s
	 * @param xadesPaths {@link XAdESPaths}
	 */
	public XAdESTimestampDataBuilder(final Element signature, final List<Reference> references, final XAdESPaths xadesPaths) {
		this.signature = signature;
		this.references = references;
		this.xadesPaths = xadesPaths;
	}

	@Override
	public DSSDocument getContentTimestampData(final TimestampToken timestampToken) {
		final TimestampType timeStampType = timestampToken.getTimeStampType();
		if (!timeStampType.isContentTimestamp()) {
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
				LOG.trace("IndividualDataObjectsTimestampData/AllDataObjectsTimestampData bytes:");
				LOG.trace(new String(byteArray));
			}
			return new InMemoryDocument(byteArray);
		} catch (IOException | XMLSecurityException e) {
			if (LOG.isDebugEnabled()) {
				LOG.warn("Unable to extract IndividualDataObjectsTimestampData/AllDataObjectsTimestampData. Reason : {}", e.getMessage(), e);
			} else {
				LOG.warn("Unable to extract IndividualDataObjectsTimestampData/AllDataObjectsTimestampData. Reason : {}", e.getMessage());
			}
		}
		return null;

	}
	
	private byte[] getReferenceBytes(final Reference reference, final String canonicalizationMethod) throws XMLSecurityException {
		/*
		 * 1) process the retrieved ds:Reference element according to the reference-processing model of XMLDSIG [1]
		 * clause 4.4.3.2;
		 */
		byte[] referencedBytes = reference.getReferencedBytes();
		/*
		 * 2) if the result is a XML node set, canonicalize it as specified in clause 4.5; and
		 */
		if (ReferenceOutputType.NODE_SET.equals(DSSXMLUtils.getReferenceOutputType(reference)) && DomUtils.isDOM(referencedBytes)) {
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
	 * @param timestampToken {@link TimestampToken}
	 * @return TRUE all timestamp includes hasve referencedData attribute set to true, FALSE otherwise
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
			return !DSSXMLUtils.isSignedProperties(reference, xadesPaths);
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
	public DSSDocument getSignatureTimestampData(final TimestampToken timestampToken) {
		byte[] timestampData = getSignatureTimestampData(timestampToken, null);
		return new InMemoryDocument(timestampData);
	}
	
	/**
	 * Returns SignatureTimestamp Data for a new Timestamp
	 *
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @return timestamp data
	 */
	public byte[] getSignatureTimestampData(final String canonicalizationMethod) {
		return getSignatureTimestampData(null, canonicalizationMethod);
	}

	protected byte[] getSignatureTimestampData(final TimestampToken timestampToken, String canonicalizationMethod) {
		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;
		try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
			writeCanonicalizedValue(XMLDSigPaths.SIGNATURE_VALUE_PATH, canonicalizationMethod, buffer);
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
	public DSSDocument getTimestampX1Data(final TimestampToken timestampToken) {
		byte[] timestampX1Data = getTimestampX1Data(timestampToken, null, null);
		return new InMemoryDocument(timestampX1Data);
	}
	
	/**
	 * Returns SigAndRefsTimestamp/SigAndRefsTimestampV2 message-imprint data for a new timestamp
	 *
	 * @param canonicalizationMethod
	 *              {@link String} canonicalization method to use
	 * @param en319132
	 *              defines if the timestamp shall be created accordingly to ETSI EN 319 132-1 (SigAndRefsTimestampV2)
	 * @return message-imprint octets
	 */
	public byte[] getTimestampX1Data(final String canonicalizationMethod, boolean en319132) {
		return getTimestampX1Data(null, canonicalizationMethod, en319132);
	}

	/**
	 * Computes the message-imprint for SigAndRefsTimestamp/SigAndRefsTimestampV2
	 *
	 * @param timestampToken
	 *              {@link TimestampToken} on signature validation
	 * @param canonicalizationMethod
	 *              {@link String} canonicalization method to use
	 * @param en319132
	 *              defines if the timestamp shall be created accordingly to ETSI EN 319 132-1 (SigAndRefsTimestampV2)
	 * @return message-imprint octets
	 */
	protected byte[] getTimestampX1Data(final TimestampToken timestampToken, String canonicalizationMethod, Boolean en319132) {
		XAdESAttribute timestampAttribute = timestampToken != null ? (XAdESAttribute) timestampToken.getTimestampAttribute() : null;

		canonicalizationMethod = timestampToken != null ?
				timestampToken.getCanonicalizationMethod() : canonicalizationMethod;
		en319132 = timestampToken != null ?
				checkAttributeNameMatches(timestampAttribute, XAdES141Element.SIG_AND_REFS_TIMESTAMP_V2) : en319132;

		/**
		 * A.1.5.1 The SigAndRefsTimeStampV2 qualifying property (A.1.5.1.2 Not distributed case)
		 *
		 * The input to the electronic time-stamp's message imprint computation input
		 * shall be the result of taking in order each of the XAdES components listed below,
		 * canonicalizing each one as specified in clause 4.5, and concatenating
		 * the resulting octet streams:
		 */
		try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {
			/**
			 * 1) The ds:SignatureValue element.
			 */
			writeCanonicalizedValue(XMLDSigPaths.SIGNATURE_VALUE_PATH, canonicalizationMethod, buffer);

			/**
			 * 2) Those among the following unsigned qualifying properties that appear before SigAndRefsTimeStampV2,
			 * in their order of appearance within the UnsignedSignatureProperties element:
			 */

			// Canonicalization copy is used in order to allow XL/A levels creation
			Element unsignedProperties = getUnsignedSignaturePropertiesCanonicalizationCopy();
			if (unsignedProperties == null) {
				throw new NullPointerException(xadesPaths.getUnsignedSignaturePropertiesPath());
			}

			XAdESUnsignedSigProperties xadesUnsignedSigProperties = new XAdESUnsignedSigProperties(unsignedProperties, xadesPaths);
			for (XAdESAttribute xadesAttribute : xadesUnsignedSigProperties.getAttributes()) {
				if (timestampAttribute != null && timestampAttribute.equals(xadesAttribute)) {
					break;
				}

				if (en319132) {
					/**
					 * - The SignatureTimeStamp qualifying properties.
					 * - The CompleteCertificateRefsV2 qualifying property.
					 * - The CompleteRevocationRefs qualifying property.
					 * - The AttributeCertificateRefsV2 qualifying property if it is present. And
					 * - The AttributeRevocationRefs qualifying property if it is present.
					 */
					if (checkAttributeNameMatches(xadesAttribute, XAdES132Element.SIGNATURE_TIMESTAMP,
							XAdES141Element.COMPLETE_CERTIFICATE_REFS_V2, XAdES132Element.COMPLETE_REVOCATION_REFS,
							XAdES141Element.ATTRIBUTE_CERTIFICATE_REFS_V2, XAdES132Element.ATTRIBUTE_REVOCATION_REFS)) {
						writeCanonicalizedValue(xadesAttribute, canonicalizationMethod, buffer);
					}

				} else {
					/**
					 * TS 101 903 v1.4.2 : 7.5.1 The SigAndRefsTimeStamp element (7.5.1.1 Not distributed case)
					 *
					 * 2) Those among the following unsigned properties that appear before SigAndRefsTimeStamp,
					 * in their order of appearance within the UnsignedSignatureProperties element:
					 * - SignatureTimeStamp elements.
					 * - The CompleteCertificateRefs element.
					 * - The CompleteRevocationRefs element.
					 * - The AttributeCertificateRefs element if this property is present.
					 * - The AttributeRevocationRefs element if this property is present.
					 */
					if (checkAttributeNameMatches(xadesAttribute, XAdES132Element.SIGNATURE_TIMESTAMP,
							XAdES132Element.COMPLETE_CERTIFICATE_REFS, XAdES132Element.COMPLETE_REVOCATION_REFS,
							XAdES132Element.ATTRIBUTE_CERTIFICATE_REFS, XAdES132Element.ATTRIBUTE_REVOCATION_REFS)) {
						writeCanonicalizedValue(xadesAttribute, canonicalizationMethod, buffer);
					}
				}
			}

			final byte[] byteArray = buffer.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("X1Timestamp (SigAndRefsTimeStamp) canonicalized string : \n{}", new String(byteArray));
			}
			return byteArray;
		} catch (IOException e) {
			throw new DSSException("Error when computing the SigAndRefsTimeStamp (X1Timestamp)", e);
		}
	}

	@Override
	public DSSDocument getTimestampX2Data(final TimestampToken timestampToken) {
		byte[] timestampX2Data = getTimestampX2Data(timestampToken, null, null);
		return new InMemoryDocument(timestampX2Data);
	}
	
	/**
	 * Returns RefsOnlyTimestamp/RefsOnlyTimestampV2 message-imprint data for a new timestamp
	 *
	 * @param canonicalizationMethod
	 *              {@link String} canonicalization method to use
	 * @param en319132
	 *              defines if the timestamp shall be created accordingly to ETSI EN 319 132-1 (RefsOnlyTimestampV2)
	 * @return message-imprint octets
	 */
	public byte[] getTimestampX2Data(final String canonicalizationMethod, boolean en319132) {
		return getTimestampX2Data(null, canonicalizationMethod, en319132);
	}

	/**
	 * Computes the message-imprint for RefsOnlyTimestamp/RefsOnlyTimestampV2
	 *
	 * @param timestampToken
	 *              {@link TimestampToken} on signature validation
	 * @param canonicalizationMethod
	 *              {@link String} canonicalization method to use
	 * @param en319132
	 *              defines if the timestamp shall be created accordingly to ETSI EN 319 132-1 (RefsOnlyTimestampV2)
	 * @return message-imprint octets
	 */
	protected byte[] getTimestampX2Data(final TimestampToken timestampToken, String canonicalizationMethod, Boolean en319132) {
		XAdESAttribute timestampAttribute = timestampToken != null ? (XAdESAttribute) timestampToken.getTimestampAttribute() : null;

		canonicalizationMethod = timestampToken != null ? timestampToken.getCanonicalizationMethod() : canonicalizationMethod;
		en319132 = timestampToken != null ?
				checkAttributeNameMatches(timestampAttribute, XAdES141Element.REFS_ONLY_TIMESTAMP_V2) : en319132;

		/**
		 * A.1.5.2 The RefsOnlyTimeStampV2 qualifying property (A.1.5.2.2 Not distributed case)
		 *
		 * The electronic time-stamp's message imprint computation input shall be
		 * the result of taking those of the qualifying unsigned properties listed below
		 * that appear before the RefsOnlyTimeStampV2 in their order of appearance within
		 * the UnsignedSignatureProperties element, canonicalizing each one as specified in clause 4.5,
		 * and concatenating the resulting octet streams:
		 */
		try (ByteArrayOutputStream buffer = new ByteArrayOutputStream()) {


			// Canonicalization copy is used in order to allow XL/A levels creation
			Element unsignedProperties = getUnsignedSignaturePropertiesCanonicalizationCopy();
			if (unsignedProperties == null) {
				throw new NullPointerException(xadesPaths.getUnsignedSignaturePropertiesPath());
			}

			XAdESUnsignedSigProperties xadesUnsignedSigProperties = new XAdESUnsignedSigProperties(unsignedProperties, xadesPaths);
			for (XAdESAttribute xadesAttribute : xadesUnsignedSigProperties.getAttributes()) {
				if (timestampAttribute != null && timestampAttribute.equals(xadesAttribute)) {
					break;
				}

				// Use RefsOnlyTimeStampV2 on signature creation/extension
				if (en319132) {
					/**
					 * - The CompleteCertificateRefsV2 qualifying property.
					 * - The CompleteRevocationRefs qualifying property.
					 * - The AttributeCertificateRefsV2 qualifying property if it is present. And
					 * - The AttributeRevocationRefs qualifying property if it is present.
					 */
					if (checkAttributeNameMatches(xadesAttribute,
							XAdES141Element.COMPLETE_CERTIFICATE_REFS_V2, XAdES132Element.COMPLETE_REVOCATION_REFS,
							XAdES141Element.ATTRIBUTE_CERTIFICATE_REFS_V2, XAdES132Element.ATTRIBUTE_REVOCATION_REFS)) {
						writeCanonicalizedValue(xadesAttribute, canonicalizationMethod, buffer);
					}

				} else {
					/**
					 * TS 101 903 v1.4.2 : 7.5.1 The SigAndRefsTimeStamp element (7.5.1.1 Not distributed case)
					 *
					 * - The CompleteCertificateRefs element.
					 * - The CompleteRevocationRefs element.
					 * - The AttributeCertificateRefs element if this property is present.
					 * - The AttributeRevocationRefs element if this property is present.
					 */
					if (checkAttributeNameMatches(xadesAttribute,
							XAdES132Element.COMPLETE_CERTIFICATE_REFS, XAdES132Element.COMPLETE_REVOCATION_REFS,
							XAdES132Element.ATTRIBUTE_CERTIFICATE_REFS, XAdES132Element.ATTRIBUTE_REVOCATION_REFS)) {
						writeCanonicalizedValue(xadesAttribute, canonicalizationMethod, buffer);
					}
				}
			}

			final byte[] byteArray = buffer.toByteArray();
			if (LOG.isTraceEnabled()) {
				LOG.trace("TimestampX2Data (RefsOnlyTimeStamp) canonicalized string : \n{}", new String(byteArray));
			}
			return byteArray;
		} catch (IOException e) {
			throw new DSSException("Error when computing the RefsOnlyTimeStamp (TimestampX2D)", e);
		}
	}
	
	@Override
	public DSSDocument getArchiveTimestampData(final TimestampToken timestampToken) {
		// timestamp validation
		try {
			byte[] archiveTimestampData = getArchiveTimestampData(timestampToken, null);
			return new InMemoryDocument(archiveTimestampData);
		} catch (DSSException e) {
			LOG.error("Unable to get data for TimestampToken with Id '{}'. Reason : {}", timestampToken.getDSSIdAsString(), e.getMessage(), e);
			return null;
		}
	}
	
	/**
	 * Returns ArchiveTimestamp message-imprint data for a new timestamp
	 *
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @return message-imprint octets
	 */
	public byte[] getArchiveTimestampData(final String canonicalizationMethod) {
		// timestamp creation
		return getArchiveTimestampData(null, canonicalizationMethod);
	}

	/**
	 * Gathers the data to be used to calculate the hash value sent to the TSA (messageImprint).
	 *
	 * @param timestampToken
	 *            {@code TimestampToken} to validate, or {@code null} when adding a new archive timestamp
	 * @param canonicalizationMethod
	 *            {@link String}
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
			 * whatever the signer wants to sign including the SignedProperties element.
			 * Process each one as indicated below:<br>
			 * - Process the retrieved ds:Reference element according to the reference processing model of XMLDSIG.<br>
			 * - If the result is a XML node set, canonicalize it. If ds:Canonicalization is present, the algorithm
			 * indicated by this element is used. If not,
			 * the standard canonicalization method specified by XMLDSIG is used.<br>
			 * - Concatenate the resulting octets to the final octet stream.
			 */

			/**
			 * The references are already calculated {@see #checkSignatureIntegrity()}
			 */
			final Set<String> referenceURIs = new HashSet<>();
			for (final Reference reference : references) {
				referenceURIs.add(DomUtils.getId(reference.getURI()));
				writeReferenceBytes(reference, canonicalizationMethod, buffer);
			}

			/**
			 * 3) Take the following XMLDSIG elements in the order they are listed below, canonicalize each one and
			 * concatenate each resulting octet stream to the final octet stream:<br>
			 * - The ds:SignedInfo element.<br>
			 * - The ds:SignatureValue element.<br>
			 * - The ds:KeyInfo element, if present.
			 */
			writeCanonicalizedValue(XMLDSigPaths.SIGNED_INFO_PATH, canonicalizationMethod, buffer);
			writeCanonicalizedValue(XMLDSigPaths.SIGNATURE_VALUE_PATH, canonicalizationMethod, buffer);
			writeCanonicalizedValue(XMLDSigPaths.KEY_INFO_PATH, canonicalizationMethod, buffer);
			/**
			 * 4) Take the unsigned signature properties that appear before the current xadesv141:ArchiveTimeStamp in
			 * the order they appear within the xades:UnsignedSignatureProperties, canonicalize each one and
			 * concatenate each resulting octet stream to the final octet stream.
			 * While concatenating the following rules apply:
			 */
			writeTimestampedUnsignedProperties(timestampToken, canonicalizationMethod, buffer);
			
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
			
		} catch (Exception e) {
			throw new DSSException(String.format("An error occurred while building a message imprint data. Reason : %s", e.getMessage()), e);
		}
	}
	
	private void writeReferenceBytes(final Reference reference, final String canonicalizationMethod,
			ByteArrayOutputStream buffer) throws IOException {
		try {
			final byte[] referencedBytes = getReferenceBytes(reference, canonicalizationMethod);
			if (referencedBytes != null) {
				buffer.write(referencedBytes);
			} else {
				throw new DSSException(String.format("No binaries found for URI '%s'", reference.getURI()));
			}
		} catch (XMLSecurityException e) {
			throw new DSSException(String.format("Unable to retrieve content for URI '%s' : %s", reference.getURI(), e.getMessage()), e);
		}
	}

	private void writeCanonicalizedValue(final String xPathString, final String canonicalizationMethod, final ByteArrayOutputStream buffer) throws IOException {
		final Element element = DomUtils.getElement(signature, xPathString);
		if (element != null) {
			buffer.write(DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, element));
		}
	}

	private Element getUnsignedSignaturePropertiesDom() {
		return DomUtils.getElement(signature, xadesPaths.getUnsignedSignaturePropertiesPath());
	}
	
	private Element getUnsignedSignaturePropertiesCanonicalizationCopy() {
		/*
         * This is the work around. The issue was reported on:
         * https://issues.apache.org/jira/browse/SANTUARIO-139.
         * Namespaces are not added to canonicalizer for new created elements.
         * The binaries need to be parsed at a new instance of Document
         */
        final byte[] canonicalizedDoc = DSSXMLUtils.serializeNode(signature.getOwnerDocument());
        Document recreatedDocument = DomUtils.buildDOM(canonicalizedDoc);
        Element recreatedSignature = DomUtils.getElementById(recreatedDocument, DSSXMLUtils.getIDIdentifier(signature));
        return DomUtils.getElement(recreatedSignature, xadesPaths.getUnsignedSignaturePropertiesPath());
	}
	
	private void writeTimestampedUnsignedProperties(TimestampToken timestampToken, String canonicalizationMethod,
													ByteArrayOutputStream buffer) throws IOException {

		XAdESUnsignedSigProperties xadesUnsignedSigProperties = getXAdESUnsignedSignatureProperties(timestampToken);
		for (XAdESAttribute xadesAttribute : xadesUnsignedSigProperties.getAttributes()) {

			/*
			 * In the SD-DSS implementation when validating the signature
			 * the framework will not add missing data.
			 * To do so the signature must be extended.
			 */
			// if (xadesAttribute.getName().equals("CertificateValues")) {
			/*
			 * - The xades:CertificateValues property MUST be added if it is not already present and the ds:KeyInfo
			 * element does not contain the full set of
			 * certificates used to validate the electronic signature.
			 */
			// } else if (xadesAttribute.getName().equals("RevocationValues")) {
			/*
			 * - The xades:RevocationValues property MUST be added if it is not already present and the ds:KeyInfo
			 * element does not contain the revocation
			 * information that has to be shipped with the electronic signature
			 */
			// } else if (xadesAttribute.getName().equals("AttrAuthoritiesCertValues")) {
			/*
			 * - The xades:AttrAuthoritiesCertValues property MUST be added if not already present and the following
			 * conditions are true: there exist an
			 * attribute certificate in the signature AND a number of certificates that have been used in its
			 * validation do not appear in CertificateValues.
			 * Its content will satisfy with the rules specified in clause 7.6.3.
			 */
			// } else if (xadesAttribute.getName().equals("AttributeRevocationValues")) {
			/*
			 * - The xades:AttributeRevocationValues property MUST be added if not already present and there the
			 * following conditions are true: there exist
			 * an attribute certificate AND some revocation data that have been used in its validation do not appear
			 * in RevocationValues. Its content will
			 * satisfy with the rules specified in clause 7.6.4.
			 */
			// } else
			if (timestampToken != null && timestampToken.getTimestampAttribute().equals(xadesAttribute)) {
				break;
				
			// } else if (XAdES141Element.TIMESTAMP_VALIDATION_DATA.isSameTagName(xadesAttribute.getName())) {
			/*
			 * ETSI TS 101 903 V1.4.2 (2010-12) 8.1 The new XAdESv141:TimeStampValidationData element ../.. This
			 * element is specified to serve as an
			 * optional container for validation data required for carrying a full verification of time-stamp
			 * tokens embedded within any of the
			 * different time-stamp containers defined in the present document. ../.. 8.1.1 Use of URI attribute
			 * ../.. a new
			 * xades141:TimeStampValidationData element SHALL be created containing the missing validation data
			 * information and it SHALL be added as a
			 * child of UnsignedSignatureProperties elements immediately after the respective time-stamp
			 * certificateToken container element.
			 */
			}

			writeCanonicalizedValue(xadesAttribute, canonicalizationMethod, buffer);
		}
	}

	private XAdESUnsignedSigProperties getXAdESUnsignedSignatureProperties(TimestampToken timestampToken) {
		final Element unsignedProperties;
		if (timestampToken == null) {
			// timestamp creation
			unsignedProperties = getUnsignedSignaturePropertiesCanonicalizationCopy();
		} else {
			unsignedProperties = getUnsignedSignaturePropertiesDom();;
		}
		if (unsignedProperties == null) {
			throw new NullPointerException(xadesPaths.getUnsignedSignaturePropertiesPath());
		}

		return new XAdESUnsignedSigProperties(unsignedProperties, xadesPaths);
	}

	private boolean checkAttributeNameMatches(XAdESAttribute attribute, DSSElement... elements) {
		if (attribute != null) {
			return Arrays.stream(elements).map(e -> e.getTagName()).anyMatch(attribute.getName()::equals);
		}
		return false;
	}

	private void writeCanonicalizedValue(XAdESAttribute attribute, String canonicalizationMethod,
										 ByteArrayOutputStream buffer) throws IOException {
		byte[] canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, attribute.getElement());
		if (LOG.isTraceEnabled()) {
			LOG.trace("{}: Canonicalization: {} : \n{}", attribute.getName(), canonicalizationMethod,
					new String(canonicalizedValue));
		}
		buffer.write(canonicalizedValue);
	}

	/**
	 * This method returns the list of ds:Object elements for the current signature element.
	 *
	 * @return {@link NodeList}
	 */
	private NodeList getObjects() {
		return DomUtils.getNodeList(signature, XMLDSigPaths.OBJECT_PATH);
	}
	
	private void writeObjectBytes(final NodeList objects, final Set<String> referenceURIs, String canonicalizationMethod, boolean xades141,
			ByteArrayOutputStream buffer) throws IOException {
		for (int ii = 0; ii < objects.getLength(); ii++) {

			final Node node = objects.item(ii);
			final Node qualifyingProperties = DomUtils.getElement(node, xadesPaths.getCurrentQualifyingPropertiesPath());
			if (qualifyingProperties != null) {
				continue;
			}
			if (!xades141) {
				/**
				 * !!! ETSI TS 101 903 V1.3.2 (2006-03)
				 * 5) Take any ds:Object element in the signature that is not referenced by any ds:Reference within
				 * ds:SignedInfo, except that one containing the QualifyingProperties element. Canonicalize each one
				 * and concatenate each resulting octet tream to the final octet stream.
				 * If ds:Canonicalization is present, the algorithm indicated by this element is used.
				 * If not, the standard canonicalization method specified by XMLDSIG is used.
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
			byte[] canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, node);
			buffer.write(canonicalizedValue);
		}
		
	}

}

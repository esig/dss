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

import eu.europa.esig.dss.xml.XMLCanonicalizer;
import eu.europa.esig.dss.xml.DomUtils;
import eu.europa.esig.dss.jaxb.common.definition.DSSElement;
import eu.europa.esig.xmldsig.definition.XMLDSigPaths;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.spi.DSSMessageDigestCalculator;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.x509.tsp.TimestampInclude;
import eu.europa.esig.dss.validation.timestamp.TimestampMessageDigestBuilder;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.xades.DSSXMLUtils;
import eu.europa.esig.xades.definition.XAdESPaths;
import eu.europa.esig.xades.definition.xades132.XAdES132Element;
import eu.europa.esig.xades.definition.xades141.XAdES141Element;
import eu.europa.esig.dss.xades.reference.ReferenceOutputType;
import eu.europa.esig.dss.xades.validation.XAdESAttribute;
import eu.europa.esig.dss.xades.validation.XAdESSignature;
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

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Builds a message-imprint for XAdES timestamps
 */
public class XAdESTimestampMessageDigestBuilder implements TimestampMessageDigestBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESTimestampMessageDigestBuilder.class);

	/** The error message to be thrown in case of a message-imprint build error */
	private static final String MESSAGE_IMPRINT_ERROR = "Unable to compute message-imprint for TimestampToken. Reason : %s";

	/** The error message to be thrown in case of a message-imprint build error for a timestamp */
	private static final String MESSAGE_IMPRINT_ERROR_WITH_ID = "Unable to compute message-imprint for TimestampToken with Id '%s'. Reason : %s";

	/** List of XAdES signature references */
	private final List<Reference> references;

	/** The signature element */
	private final Element signature;

	/** The XAdES XPaths to use */
	private final XAdESPaths xadesPaths;

	/** The digest algorithm to be used for message-imprint digest computation */
	private DigestAlgorithm digestAlgorithm;

	/** Timestamp token to compute message-digest for */
	private TimestampToken timestampToken;

	/** The canonicalization algorithm to be used for message-imprint computation */
	private String canonicalizationAlgorithm;

	/** Identifies whether message-imprint shall be built as per EN 319 132-1 standard (against old version) */
	private boolean en319132;

	/** A signature attribute corresponding to the time-stamp */
	private XAdESAttribute timestampAttribute;

	/**
	 * Default constructor to be used for a new timestamp creation.
	 * This constructor requires certain properties to be provided for message-digest computation (see available setters).
	 *
	 * @param signature {@link XAdESSignature} containing timestamps to calculate message-imprint digest for
	 * @param digestAlgorithm {@link DigestAlgorithm} to be used for message-imprint digest computation
	 */
	public XAdESTimestampMessageDigestBuilder(final XAdESSignature signature, final DigestAlgorithm digestAlgorithm) {
		this(signature);
		Objects.requireNonNull(digestAlgorithm, "DigestAlgorithm cannot be null!");
		this.digestAlgorithm = digestAlgorithm;
	}

	/**
	 * Constructor to be used for existing timestamp message-imprint computation.
	 *
	 * @param signature {@link XAdESSignature} signature associated with the timestamp
	 * @param timestampToken {@link TimestampToken} to compute message-digest for
	 */
	public XAdESTimestampMessageDigestBuilder(final XAdESSignature signature, final TimestampToken timestampToken) {
		this(signature);
		Objects.requireNonNull(timestampToken, "TimestampToken cannot be null!");
		this.timestampToken = timestampToken;
		this.digestAlgorithm = timestampToken.getDigestAlgorithm();
		this.canonicalizationAlgorithm = timestampToken.getCanonicalizationMethod();
	}

	/**
	 * Internal constructor to instantiate required values from a signature object
	 *
	 * @param signature {@link XAdESSignature}
	 */
	private XAdESTimestampMessageDigestBuilder(final XAdESSignature signature) {
		Objects.requireNonNull(signature, "Signature cannot be null!");
		this.signature = signature.getSignatureElement();
		this.references = signature.getReferences();
		this.xadesPaths = signature.getXAdESPaths();
	}

	/**
	 * Sets the canonicalization algorithm to be used for message-digest computation
	 *
	 * @param canonicalizationAlgorithm {@link String}
	 * @return this {@link XAdESTimestampMessageDigestBuilder}
	 */
	public XAdESTimestampMessageDigestBuilder setCanonicalizationAlgorithm(String canonicalizationAlgorithm) {
		this.canonicalizationAlgorithm = canonicalizationAlgorithm;
		return this;
	}

	/**
	 * Sets whether the message-digest should be computed for a EN 319 132-1 standard timestamp token
	 *
	 * @param en319132 whether the timestamp is of EN 319 132-1 format
	 * @return this {@link XAdESTimestampMessageDigestBuilder}
	 */
	public XAdESTimestampMessageDigestBuilder setEn319132(boolean en319132) {
		this.en319132 = en319132;
		return this;
	}

	/**
	 * Sets a signature attribute corresponding to the time-stamp token.
	 * Defined also {@code en319132} based on the provided timestamp attribute.
	 *
	 * @param timestampAttribute {@link XAdESAttribute}
	 * @return this {@link XAdESTimestampMessageDigestBuilder}
	 */
	public XAdESTimestampMessageDigestBuilder setTimestampAttribute(XAdESAttribute timestampAttribute) {
		this.timestampAttribute = timestampAttribute;
		if (timestampAttribute != null) {
			this.en319132 = isEn319132TimestampToken(timestampAttribute);
		}
		return this;
	}

	@Override
	public DSSMessageDigest getContentTimestampMessageDigest() {
		// all data timestamp is considered by default
		final TimestampType timeStampType = timestampToken != null ?
				timestampToken.getTimeStampType() : TimestampType.ALL_DATA_OBJECTS_TIMESTAMP;
		if (references.isEmpty()) {
			throw new IllegalStateException("The method 'checkSignatureIntegrity' must be invoked first!");
		}

		switch (timeStampType) {
			case ALL_DATA_OBJECTS_TIMESTAMP:
				return getAllDataObjectsTimestampMessageDigest();
			case INDIVIDUAL_DATA_OBJECTS_TIMESTAMP:
				return getIndividualDataObjectsTimestampMessageDigest();
			default:
				throw new UnsupportedOperationException(String.format("The content timestamp of type '%s' is not supported!",
						timeStampType));
		}
	}

	/**
	 * Returns the computed message-imprint digest for xades132:AllDataObjectsTimestamp token
	 *
	 * @return {@link DSSMessageDigest} message-imprint digest
	 */
	protected DSSMessageDigest getAllDataObjectsTimestampMessageDigest() {
		try {
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
			for (final Reference reference : references) {
				if (!DSSXMLUtils.isSignedProperties(reference, xadesPaths)) {
					byte[] referenceBytes = getReferenceBytes(reference, canonicalizationAlgorithm);
					digestCalculator.update(referenceBytes);
				}
			}
			final DSSMessageDigest messageDigest = digestCalculator.getMessageDigest();
			if (LOG.isTraceEnabled()) {
				LOG.trace(String.format("AllDataObjectsTimestampData message-imprint: %s", messageDigest));
			}
			return messageDigest;

		} catch (XMLSecurityException e) {
			if (LOG.isDebugEnabled()) {
				LOG.warn("Unable to extract AllDataObjectsTimestampData. Reason : {}", e.getMessage(), e);
			} else {
				LOG.warn("Unable to extract AllDataObjectsTimestampData. Reason : {}", e.getMessage());
			}
		}
		return DSSMessageDigest.createEmptyDigest();
	}

	/**
	 * Returns the computed message-imprint digest for xades132:IndividualDataObjectsTimestamp token
	 *
	 * @return {@link DSSMessageDigest} message-imprint digest
	 */
	protected DSSMessageDigest getIndividualDataObjectsTimestampMessageDigest() {
		if (!checkTimestampTokenIncludes(timestampToken)) {
			throw new IllegalArgumentException("The Included referencedData attribute is either not present or set to false!");
		}

		final List<TimestampInclude> includes = timestampToken.getTimestampIncludes();
		try {
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
			for (final TimestampInclude include : includes) {
				Reference reference = getCorrespondingReference(include, references);
				if (reference != null) {
					byte[] referenceBytes = getReferenceBytes(reference, canonicalizationAlgorithm);
					digestCalculator.update(referenceBytes);
				} else {
					LOG.warn("No ds:Reference found corresponding to an IndividualDataObjectsTimestamp include " +
									"with URI '{}'!", include.getURI());
				}
			}
			DSSMessageDigest messageDigest = digestCalculator.getMessageDigest();
			if (LOG.isTraceEnabled()) {
				LOG.trace(String.format("IndividualDataObjectsTimestampData message-imprint: %s", messageDigest));
			}
			return messageDigest;

		} catch (XMLSecurityException e) {
			if (LOG.isDebugEnabled()) {
				LOG.warn("Unable to extract IndividualDataObjectsTimestampData. Reason : {}", e.getMessage(), e);
			} else {
				LOG.warn("Unable to extract IndividualDataObjectsTimestampData. Reason : {}", e.getMessage());
			}
		}
		return DSSMessageDigest.createEmptyDigest();
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
			referencedBytes = XMLCanonicalizer.createInstance(canonicalizationMethod).canonicalize(referencedBytes);
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
	 * @return TRUE all timestamp includes have referencedData attribute set to true, FALSE otherwise
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

	private Reference getCorrespondingReference(TimestampInclude timestampInclude, List<Reference> references) {
		String uri = timestampInclude.getURI();
		for (Reference reference : references) {
			if (uri.equals(reference.getId())) {
				return reference;
			}
		}
		return null;
	}

	@Override
	public DSSMessageDigest getSignatureTimestampMessageDigest() {
		try {
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
			byte[] canonicalizedValue = getCanonicalizedValue(XMLDSigPaths.SIGNATURE_VALUE_PATH, canonicalizationAlgorithm);
			digestCalculator.update(canonicalizedValue);

			final DSSMessageDigest messageDigest = digestCalculator.getMessageDigest();
			if (LOG.isTraceEnabled()) {
				LOG.trace(String.format("Signature timestamp message-imprint: %s", messageDigest));
			}
			return messageDigest;

		} catch (Exception e) {
			String errorMessage = timestampToken == null ? String.format(MESSAGE_IMPRINT_ERROR, e.getMessage()) :
					String.format(MESSAGE_IMPRINT_ERROR_WITH_ID, timestampToken.getDSSIdAsString(), e.getMessage());
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e);
			} else {
				LOG.warn(errorMessage);
			}
		}
		return DSSMessageDigest.createEmptyDigest();
	}

	@Override
	public DSSMessageDigest getTimestampX1MessageDigest() {
		try {
			/*
			 * A.1.5.1 The SigAndRefsTimeStampV2 qualifying property (A.1.5.1.2 Not distributed case)
			 *
			 * The input to the electronic time-stamp's message imprint computation input
			 * shall be the result of taking in order each of the XAdES components listed below,
			 * canonicalizing each one as specified in clause 4.5, and concatenating
			 * the resulting octet streams:
			 */
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);

			/*
			 * 1) The ds:SignatureValue element.
			 */
			byte[] canonicalizedValue = getCanonicalizedValue(XMLDSigPaths.SIGNATURE_VALUE_PATH, canonicalizationAlgorithm);
			digestCalculator.update(canonicalizedValue);

			/*
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
					/*
					 * - The SignatureTimeStamp qualifying properties.
					 * - The CompleteCertificateRefsV2 qualifying property.
					 * - The CompleteRevocationRefs qualifying property.
					 * - The AttributeCertificateRefsV2 qualifying property if it is present. And
					 * - The AttributeRevocationRefs qualifying property if it is present.
					 */
					if (checkAttributeNameMatches(xadesAttribute, XAdES132Element.SIGNATURE_TIMESTAMP,
							XAdES141Element.COMPLETE_CERTIFICATE_REFS_V2, XAdES132Element.COMPLETE_REVOCATION_REFS,
							XAdES141Element.ATTRIBUTE_CERTIFICATE_REFS_V2, XAdES132Element.ATTRIBUTE_REVOCATION_REFS)) {
						canonicalizedValue = getCanonicalizedValue(xadesAttribute, canonicalizationAlgorithm);
						digestCalculator.update(canonicalizedValue);
					}

				} else {
					/*
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
						canonicalizedValue = getCanonicalizedValue(xadesAttribute, canonicalizationAlgorithm);
						digestCalculator.update(canonicalizedValue);
					}
				}
			}

			final DSSMessageDigest messageDigest = digestCalculator.getMessageDigest();
			if (LOG.isTraceEnabled()) {
				LOG.trace(String.format("X1Timestamp (SigAndRefsTimeStamp) message-imprint: %s", messageDigest));
			}
			return messageDigest;

		} catch (Exception e) {
			String errorMessage = timestampToken == null ? String.format(MESSAGE_IMPRINT_ERROR, e.getMessage()) :
					String.format(MESSAGE_IMPRINT_ERROR_WITH_ID, timestampToken.getDSSIdAsString(), e.getMessage());
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e);
			} else {
				LOG.warn(errorMessage);
			}
		}
		return DSSMessageDigest.createEmptyDigest();
	}

	@Override
	public DSSMessageDigest getTimestampX2MessageDigest() {
		try {
			/*
			 * A.1.5.2 The RefsOnlyTimeStampV2 qualifying property (A.1.5.2.2 Not distributed case)
			 *
			 * The electronic time-stamp's message imprint computation input shall be
			 * the result of taking those of the qualifying unsigned properties listed below
			 * that appear before the RefsOnlyTimeStampV2 in their order of appearance within
			 * the UnsignedSignatureProperties element, canonicalizing each one as specified in clause 4.5,
			 * and concatenating the resulting octet streams:
			 */
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);

			// Canonicalization copy is used in order to allow XL/A level creation
			Element unsignedProperties = getUnsignedSignaturePropertiesCanonicalizationCopy();
			if (unsignedProperties == null) {
				throw new NullPointerException(xadesPaths.getUnsignedSignaturePropertiesPath());
			}

			byte[] canonicalizedValue = null;
			XAdESUnsignedSigProperties xadesUnsignedSigProperties = new XAdESUnsignedSigProperties(unsignedProperties, xadesPaths);
			for (XAdESAttribute xadesAttribute : xadesUnsignedSigProperties.getAttributes()) {
				if (timestampAttribute != null && timestampAttribute.equals(xadesAttribute)) {
					break;
				}

				// Use RefsOnlyTimeStampV2 on signature creation/extension
				if (en319132) {
					/*
					 * - The CompleteCertificateRefsV2 qualifying property.
					 * - The CompleteRevocationRefs qualifying property.
					 * - The AttributeCertificateRefsV2 qualifying property if it is present. And
					 * - The AttributeRevocationRefs qualifying property if it is present.
					 */
					if (checkAttributeNameMatches(xadesAttribute,
							XAdES141Element.COMPLETE_CERTIFICATE_REFS_V2, XAdES132Element.COMPLETE_REVOCATION_REFS,
							XAdES141Element.ATTRIBUTE_CERTIFICATE_REFS_V2, XAdES132Element.ATTRIBUTE_REVOCATION_REFS)) {
						canonicalizedValue = getCanonicalizedValue(xadesAttribute, canonicalizationAlgorithm);
						digestCalculator.update(canonicalizedValue);
					}

				} else {
					/*
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
						canonicalizedValue = getCanonicalizedValue(xadesAttribute, canonicalizationAlgorithm);
						digestCalculator.update(canonicalizedValue);
					}
				}
			}

			final DSSMessageDigest messageDigest = digestCalculator.getMessageDigest();
			if (LOG.isTraceEnabled()) {
				LOG.trace(String.format("TimestampX2Data (RefsOnlyTimeStamp) message-imprint: %s", messageDigest));
			}
			return messageDigest;

		} catch (Exception e) {
			String errorMessage = timestampToken == null ? String.format(MESSAGE_IMPRINT_ERROR, e.getMessage()) :
					String.format(MESSAGE_IMPRINT_ERROR_WITH_ID, timestampToken.getDSSIdAsString(), e.getMessage());
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e);
			} else {
				LOG.warn(errorMessage);
			}
		}
		return null;
	}

	@Override
	public DSSMessageDigest getArchiveTimestampMessageDigest() {
		try {
			if (LOG.isTraceEnabled()) {
				LOG.trace("--->Get archive timestamp data : {}", (timestampToken == null ? "--> CREATION" : "--> VALIDATION"));
			}
			/*
			 * 8.2.1 Not distributed case<br>
			 *
			 * When xadesv141:ArchiveTimeStamp and all the unsigned properties covered by its time-stamp certificateToken
			 * have the same parent, this property uses
			 * the Implicit mechanism for all the time-stamped data objects. The input to the computation of the digest
			 * value MUST be built as follows:
			 *
			 * 1) Initialize the final octet stream as an empty octet stream.
			 */
			final DSSMessageDigestCalculator digestCalculator = new DSSMessageDigestCalculator(digestAlgorithm);
			byte[] bytes = null;

			/*
			 * 2) Take all the ds:Reference elements in their order of appearance within ds:SignedInfo referencing
			 * whatever the signer wants to sign including the SignedProperties element.
			 * Process each one as indicated below:<br>
			 * - Process the retrieved ds:Reference element according to the reference processing model of XMLDSIG.<br>
			 * - If the result is a XML node set, canonicalize it. If ds:Canonicalization is present, the algorithm
			 * indicated by this element is used. If not,
			 * the standard canonicalization method specified by XMLDSIG is used.<br>
			 * - Concatenate the resulting octets to the final octet stream.
			 */

			/*
			 * The references are already calculated {@see #checkSignatureIntegrity()}
			 */
			final Set<String> referenceURIs = new HashSet<>();
			for (final Reference reference : references) {
				referenceURIs.add(DomUtils.getId(reference.getURI()));
				bytes = getReferenceBytes(reference, canonicalizationAlgorithm);
				digestCalculator.update(bytes);
			}

			/*
			 * 3) Take the following XMLDSIG elements in the order they are listed below, canonicalize each one and
			 * concatenate each resulting octet stream to the final octet stream:<br>
			 * - The ds:SignedInfo element.<br>
			 * - The ds:SignatureValue element.<br>
			 * - The ds:KeyInfo element, if present.
			 */
			bytes = getCanonicalizedValue(XMLDSigPaths.SIGNED_INFO_PATH, canonicalizationAlgorithm);
			digestCalculator.update(bytes);

			bytes = getCanonicalizedValue(XMLDSigPaths.SIGNATURE_VALUE_PATH, canonicalizationAlgorithm);
			digestCalculator.update(bytes);

			bytes = getCanonicalizedValue(XMLDSigPaths.KEY_INFO_PATH, canonicalizationAlgorithm);
			digestCalculator.update(bytes);
			/*
			 * 4) Take the unsigned signature properties that appear before the current xadesv141:ArchiveTimeStamp in
			 * the order they appear within the xades:UnsignedSignatureProperties, canonicalize each one and
			 * concatenate each resulting octet stream to the final octet stream.
			 * While concatenating the following rules apply:
			 */
			writeTimestampedUnsignedProperties(digestCalculator, timestampToken, canonicalizationAlgorithm);

			/*
			 * 5) Take all the ds:Object elements except the one containing xades:QualifyingProperties element.
			 * Canonicalize each one and concatenate each resulting octet stream to the final octet stream.
			 * If ds:Canonicalization is present, the algorithm indicated by this element is used. If not,
			 * the standard canonicalization method specified by XMLDSIG is used.
			 */
			final NodeList objects = getObjects();
			writeObjectBytes(digestCalculator, objects, referenceURIs, canonicalizationAlgorithm);

			DSSMessageDigest messageDigest = digestCalculator.getMessageDigest();
			if (LOG.isTraceEnabled()) {
				LOG.trace(String.format("ArchiveTimeStamp message-imprint: %s", messageDigest));
			}
			return messageDigest;

		} catch (Exception e) {
			String errorMessage = timestampToken == null ? String.format(MESSAGE_IMPRINT_ERROR, e.getMessage()) :
					String.format(MESSAGE_IMPRINT_ERROR_WITH_ID, timestampToken.getDSSIdAsString(), e.getMessage());
			if (LOG.isDebugEnabled()) {
				LOG.warn(errorMessage, e);
			} else {
				LOG.warn(errorMessage);
			}
		}
		return null;
	}

	private byte[] getCanonicalizedValue(final String xPathString, final String canonicalizationMethod) {
		final Element element = DomUtils.getElement(signature, xPathString);
		if (element != null) {
			final byte[] bytes = XMLCanonicalizer.createInstance(canonicalizationMethod).canonicalize(element);
			if (LOG.isTraceEnabled()) {
				LOG.trace("Canonicalized subtree string : \n{}", new String(bytes));
			}
			return bytes;
		}
		return null;
	}

	private Element getUnsignedSignaturePropertiesDom() {
		return DomUtils.getElement(signature, xadesPaths.getUnsignedSignaturePropertiesPath());
	}
	
	private Element getUnsignedSignaturePropertiesCanonicalizationCopy() {
		/*
         * This is a workaround. The issue was reported on:
         * https://issues.apache.org/jira/browse/SANTUARIO-139.
         * Namespaces are not added to canonicalizer for new created elements.
         * The binaries need to be parsed at a new instance of Document
         */
        final byte[] serializedDoc = DomUtils.serializeNode(signature.getOwnerDocument());
        Document recreatedDocument = DomUtils.buildDOM(serializedDoc);
        Element recreatedSignature = DomUtils.getElementById(recreatedDocument, DSSXMLUtils.getIDIdentifier(signature));
        return DomUtils.getElement(recreatedSignature, xadesPaths.getUnsignedSignaturePropertiesPath());
	}
	
	private void writeTimestampedUnsignedProperties(DSSMessageDigestCalculator digestCalculator,
													TimestampToken timestampToken, String canonicalizationMethod) {

		byte[] canonicalizedValue = null;
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
			if (timestampAttribute != null && timestampAttribute.equals(xadesAttribute)) {
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

			canonicalizedValue = getCanonicalizedValue(xadesAttribute, canonicalizationMethod);
			digestCalculator.update(canonicalizedValue);
		}
	}

	private XAdESUnsignedSigProperties getXAdESUnsignedSignatureProperties(TimestampToken timestampToken) {
		final Element unsignedProperties;
		if (timestampToken == null) {
			// timestamp creation
			unsignedProperties = getUnsignedSignaturePropertiesCanonicalizationCopy();
		} else {
			unsignedProperties = getUnsignedSignaturePropertiesDom();
		}
		if (unsignedProperties == null) {
			throw new NullPointerException(xadesPaths.getUnsignedSignaturePropertiesPath());
		}

		return new XAdESUnsignedSigProperties(unsignedProperties, xadesPaths);
	}

	private boolean isEn319132TimestampToken(XAdESAttribute timestampAttribute) {
		return checkAttributeNameMatches(timestampAttribute, XAdES132Element.ALL_DATA_OBJECTS_TIMESTAMP,
				XAdES132Element.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP, XAdES132Element.SIGNATURE_TIMESTAMP,
				XAdES141Element.REFS_ONLY_TIMESTAMP_V2, XAdES141Element.SIG_AND_REFS_TIMESTAMP_V2,
				XAdES141Element.ARCHIVE_TIMESTAMP);
	}

	private boolean checkAttributeNameMatches(XAdESAttribute attribute, DSSElement... elements) {
		if (attribute != null) {
			return Arrays.stream(elements).map(DSSElement::getTagName).anyMatch(attribute.getName()::equals);
		}
		return false;
	}

	private byte[] getCanonicalizedValue(XAdESAttribute attribute, String canonicalizationMethod) {
		byte[] canonicalizedValue = XMLCanonicalizer.createInstance(canonicalizationMethod).canonicalize(attribute.getElement());
		if (LOG.isTraceEnabled()) {
			LOG.trace("{}: Canonicalization: {} : \n{}", attribute.getName(), canonicalizationMethod,
					new String(canonicalizedValue));
		}
		return canonicalizedValue;
	}

	/**
	 * This method returns the list of ds:Object elements for the current signature element.
	 *
	 * @return {@link NodeList}
	 */
	private NodeList getObjects() {
		return DomUtils.getNodeList(signature, XMLDSigPaths.OBJECT_PATH);
	}
	
	private void writeObjectBytes(final DSSMessageDigestCalculator digestCalculator, final NodeList objects,
								  final Set<String> referenceURIs, String canonicalizationMethod) {
		byte[] canonicalizedValue = null;
		final boolean xades141 = (timestampToken == null) || !ArchiveTimestampType.XAdES.equals(timestampToken.getArchiveTimestampType());
		for (int ii = 0; ii < objects.getLength(); ii++) {
			final Node node = objects.item(ii);
			final Node qualifyingProperties = DomUtils.getElement(node, xadesPaths.getCurrentQualifyingPropertiesPath());
			if (qualifyingProperties != null) {
				continue;
			}
			if (!xades141) {
				/*
				 * !!! ETSI TS 101 903 V1.3.2 (2006-03)
				 * 5) Take any ds:Object element in the signature that is not referenced by any ds:Reference within
				 * ds:SignedInfo, except that one containing the QualifyingProperties element. Canonicalize each one
				 * and concatenate each resulting octet stream to the final octet stream.
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
			canonicalizedValue = XMLCanonicalizer.createInstance(canonicalizationMethod).canonicalize(node);
			digestCalculator.update(canonicalizedValue);
		}
		
	}

}

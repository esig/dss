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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import eu.europa.esig.dss.DomUtils;
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
import eu.europa.esig.dss.xades.reference.ReferenceOutputType;

public class XAdESTimestampDataBuilder implements TimestampDataBuilder {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESTimestampDataBuilder.class);
	
	private final List<Reference> references;
	private final Element signature;
	
	private final XAdESPaths xadesPaths;

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
		byte[] timestampX1Data = getTimestampX1Data(timestampToken, null);
		return new InMemoryDocument(timestampX1Data);
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
			writeCanonicalizedValue(XMLDSigPaths.SIGNATURE_VALUE_PATH, canonicalizationMethod, buffer);
			final NodeList signatureTimeStampNode = DomUtils.getNodeList(signature, xadesPaths.getSignatureTimestampsPath());
			if (signatureTimeStampNode != null) {
				for (int ii = 0; ii < signatureTimeStampNode.getLength(); ii++) {
					final Node item = signatureTimeStampNode.item(ii);
					final byte[] canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, item);
					buffer.write(canonicalizedValue);
				}
			}
			writeCanonicalizedValue(xadesPaths.getCompleteCertificateRefsPath(), canonicalizationMethod, buffer);
			writeCanonicalizedValue(xadesPaths.getCompleteRevocationRefsPath(), canonicalizationMethod, buffer);
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
	public DSSDocument getTimestampX2Data(final TimestampToken timestampToken) {
		byte[] timestampX2Data = getTimestampX2Data(timestampToken, null);
		return new InMemoryDocument(timestampX2Data);
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

			writeCanonicalizedValue(xadesPaths.getCompleteCertificateRefsPath(), canonicalizationMethod, buffer);
			writeCanonicalizedValue(xadesPaths.getCompleteRevocationRefsPath(), canonicalizationMethod, buffer);

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
	 * Returns ArchiveTimestamp Data for a new Timestamp
	 * @param canonicalizationMethod {@link String} canonicalization method to use
	 * @return timestamp data
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
			final Set<String> referenceURIs = new HashSet<>();
			for (final Reference reference : references) {
				referenceURIs.add(DomUtils.getId(reference.getURI()));
				writeReferenceBytes(reference, canonicalizationMethod, buffer);
			}

			/**
			 * 3) Take the following XMLDSIG elements in the order they are listed below, canonicalize each one and
			 * concatenate each resulting octet stream to
			 * the final octet stream:<br>
			 * - The ds:SignedInfo element.<br>
			 * - The ds:SignatureValue element.<br>
			 * - The ds:KeyInfo element, if present.
			 */
			writeCanonicalizedValue(XMLDSigPaths.SIGNED_INFO_PATH, canonicalizationMethod, buffer);
			writeCanonicalizedValue(XMLDSigPaths.SIGNATURE_VALUE_PATH, canonicalizationMethod, buffer);
			writeCanonicalizedValue(XMLDSigPaths.KEY_INFO_PATH, canonicalizationMethod, buffer);
			/**
			 * 4) Take the unsigned signature properties that appear before the current xadesv141:ArchiveTimeStamp in
			 * the order they appear within the
			 * xades:UnsignedSignatureProperties, canonicalize each one and concatenate each resulting octet stream to
			 * the final octet stream. While
			 * concatenating the following rules apply:
			 */
			final Element unsignedSignaturePropertiesDom = getUnsignedSignaturePropertiesDom();
			if (unsignedSignaturePropertiesDom == null) {
				throw new NullPointerException(xadesPaths.getUnsignedSignaturePropertiesPath());
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
        Element recreatedSignature = DomUtils.getElement(recreatedDocument, ".//*" + DomUtils.getXPathByIdAttribute(DSSXMLUtils.getIDIdentifier(signature)));
        return DomUtils.getElement(recreatedSignature, xadesPaths.getUnsignedSignaturePropertiesPath());
	}
	
	private void writeTimestampedUnsignedProperties(final Element unsignedSignaturePropertiesDom, TimestampToken timestampToken, 
			String canonicalizationMethod, ByteArrayOutputStream buffer) throws IOException {
		
		final NodeList unsignedProperties;
		if (timestampToken == null) {
			// timestamp creation
			unsignedProperties = getUnsignedSignaturePropertiesCanonicalizationCopy().getChildNodes();
		} else {
			unsignedProperties = unsignedSignaturePropertiesDom.getChildNodes();
		}
		
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
			if (XAdES132Element.ARCHIVE_TIMESTAMP.isSameTagName(localName) && timestampToken != null) {
				// skip the octets extraction when the current timestamp is found (validation)
				int hashCode = unsignedSignaturePropertiesDom.getChildNodes().item(ii).hashCode();
				if (timestampToken.getHashCode() == hashCode) {
					break;
				}
				
			// } else if (XAdES141Element.TIMESTAMP_VALIDATION_DATA.isSameTagName(localName)) {
			/*
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
			
			byte[] canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, node);
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
			byte[] canonicalizedValue = DSSXMLUtils.canonicalizeSubtree(canonicalizationMethod, node);
			buffer.write(canonicalizedValue);
		}
		
	}

}

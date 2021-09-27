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
package eu.europa.esig.dss.diagnostic;

import eu.europa.esig.dss.diagnostic.jaxb.XmlAbstractToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificateToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocationToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureField;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Provides a user-friendly interface for dealing with JAXB {@code XmlTimestamp} object
 */
public class TimestampWrapper extends AbstractTokenProxy {

	/** The wrapped XmlTimestamp */
	private final XmlTimestamp timestamp;
	
	/**
	 * Default constructor
	 *
	 * @param timestamp {@link XmlTimestamp}
	 */
	public TimestampWrapper(XmlTimestamp timestamp) {
		Objects.requireNonNull(timestamp, "XmlTimestamp cannot be null!");
		this.timestamp = timestamp;
	}

	@Override
	public String getId() {
		return timestamp.getId();
	}

	@Override
	protected XmlBasicSignature getCurrentBasicSignature() {
		return timestamp.getBasicSignature();
	}

	@Override
	protected List<XmlChainItem> getCurrentCertificateChain() {
		return timestamp.getCertificateChain();
	}

	@Override
	protected XmlSigningCertificate getCurrentSigningCertificate() {
		return timestamp.getSigningCertificate();
	}

	@Override
	public FoundCertificatesProxy foundCertificates() {
		return new FoundCertificatesProxy(timestamp.getFoundCertificates());
	}

	@Override
	public FoundRevocationsProxy foundRevocations() {
		return new FoundRevocationsProxy(timestamp.getFoundRevocations());
	}

	/**
	 * Returns the type of the timestamp
	 *
	 * @return {@link TimestampType}
	 */
	public TimestampType getType() {
		return timestamp.getType();
	}
	
	/**
	 * Returns archive timestamp type, if applicable
	 *
	 * NOTE: returns null for non archive timestamps
	 *
	 * @return {@link ArchiveTimestampType}
	 */
	public ArchiveTimestampType getArchiveTimestampType() {
		return timestamp.getArchiveTimestampType();
	}

	/**
	 * Returns the indicated production time of the timestamp
	 *
	 * @return {@link Date}
	 */
	public Date getProductionTime() {
		return timestamp.getProductionTime();
	}

	/**
	 * Returns message-imprint {@code XmlDigestMatcher}
	 *
	 * @return {@link XmlDigestMatcher}
	 */
	public XmlDigestMatcher getMessageImprint() {
		for (XmlDigestMatcher digestMatcher : getDigestMatchers()) {
			if (DigestMatcherType.MESSAGE_IMPRINT.equals(digestMatcher.getType())) {
				return digestMatcher;
			}
		}
		return null;
	}

	/**
	 * Indicates if the message-imprint is found (all the required data for message-imprint computation is present)
	 *
	 * @return TRUE if the message-imprint data is found, FALSE otherwise
	 */
	public boolean isMessageImprintDataFound() {
		XmlDigestMatcher messageImprint = getMessageImprint();
		if (messageImprint != null) {
			return messageImprint.isDataFound();
		}
		return false;
	}

	/**
	 * Indicates if the message-imprint is intact (matches the computed message-imprint)
	 *
	 * @return TRUE if the message-imprint data is intact, FALSE otherwise
	 */
	public boolean isMessageImprintDataIntact() {
		XmlDigestMatcher messageImprint = getMessageImprint();
		if (messageImprint != null) {
			return messageImprint.isDataIntact();
		}
		return false;
	}

	/**
	 * Gets name of the timestamp file, when applicable
	 *
	 * @return {@link String} file name
	 */
	public String getFilename() {
		return timestamp.getTimestampFilename();
	}

	@Override
	public List<XmlDigestMatcher> getDigestMatchers() {
		return timestamp.getDigestMatchers();
	}

	/**
	 * Returns a complete list of all {@link XmlTimestampedObject}s covered by the
	 * timestamp
	 * 
	 * @return list of {@link XmlTimestampedObject}s
	 */
	public List<XmlTimestampedObject> getTimestampedObjects() {
		return timestamp.getTimestampedObjects();
	}

	/**
	 * Returns a list of {@link SignatureWrapper}s covered be the current timestamp
	 * 
	 * @return list of {@link SignatureWrapper}s
	 */
	public List<SignatureWrapper> getTimestampedSignatures() {
		List<SignatureWrapper> signatures = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.SIGNATURE);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlSignature) {
				signatures.add(new SignatureWrapper((XmlSignature) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.SIGNATURE));
			}
		}
		return signatures;
	}

	/**
	 * Returns a list of certificates covered be the current timestamp
	 * 
	 * @return list of {@link CertificateWrapper}s
	 */
	public List<CertificateWrapper> getTimestampedCertificates() {
		List<CertificateWrapper> certificates = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.CERTIFICATE);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlCertificate) {
				certificates.add(new CertificateWrapper((XmlCertificate) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.CERTIFICATE));
			}
		}
		return certificates;
	}

	/**
	 * Returns a list of revocation data covered be the current timestamp
	 * 
	 * @return list of {@link RevocationWrapper}s
	 */
	public List<RevocationWrapper> getTimestampedRevocations() {
		List<RevocationWrapper> revocations = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.REVOCATION);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlRevocation) {
				revocations.add(new RevocationWrapper((XmlRevocation) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.REVOCATION));
			}
		}
		return revocations;
	}

	/**
	 * Returns a list of timestamps covered be the current timestamp
	 * 
	 * @return list of {@link TimestampWrapper}s
	 */
	public List<TimestampWrapper> getTimestampedTimestamps() {
		List<TimestampWrapper> timestamps = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.TIMESTAMP);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlTimestamp) {
				timestamps.add(new TimestampWrapper((XmlTimestamp) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.TIMESTAMP));
			}
		}
		return timestamps;
	}

	/**
	 * Returns a list of Signed data covered be the current timestamp
	 * 
	 * @return list of {@link SignerDataWrapper}s
	 */
	public List<SignerDataWrapper> getTimestampedSignedData() {
		List<SignerDataWrapper> timestamps = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.SIGNED_DATA);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlSignerData) {
				timestamps.add(new SignerDataWrapper((XmlSignerData) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.SIGNED_DATA));
			}
		}
		return timestamps;
	}

	/**
	 * Indicates if the signing certificate reference is present within the timestamp token and
	 * matches the actual signing certificate
	 *
	 * @return TRUE if the signing certificate is unambiguously identified, FALSE otherwise
	 */
	public boolean isSigningCertificateIdentified() {
		CertificateWrapper signingCertificate = getSigningCertificate();
		CertificateRefWrapper signingCertificateReference = getSigningCertificateReference();
		if (signingCertificate != null && signingCertificateReference != null) {
			return signingCertificateReference.isDigestValueMatch() && 
					(!signingCertificateReference.isIssuerSerialPresent() || signingCertificateReference.isIssuerSerialMatch());
		}
		return false;
	}

	private List<XmlAbstractToken> getTimestampedObjectsByCategory(TimestampedObjectType category) {
		List<XmlAbstractToken> timestampedObjectIds = new ArrayList<>();
		for (XmlTimestampedObject timestampedObject : getTimestampedObjects()) {
			if (category == timestampedObject.getCategory()) {
				timestampedObjectIds.add(timestampedObject.getToken());
			}
		}
		return timestampedObjectIds;
	}

	/**
	 * Returns a list of all OrphanTokens
	 * 
	 * @return list of {@link OrphanTokenWrapper}s
	 */
	public List<OrphanTokenWrapper> getAllTimestampedOrphanTokens() {
		List<OrphanTokenWrapper> timestampedObjectIds = new ArrayList<>();
		timestampedObjectIds.addAll(getTimestampedOrphanCertificates());
		timestampedObjectIds.addAll(getTimestampedOrphanRevocations());
		return timestampedObjectIds;
	}

	/**
	 * Returns a list of OrphanCertificateTokens
	 * 
	 * @return list of orphan certificates
	 */
	public List<OrphanCertificateTokenWrapper> getTimestampedOrphanCertificates() {
		List<OrphanCertificateTokenWrapper> orphanCertificates = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.ORPHAN_CERTIFICATE);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlOrphanCertificateToken) {
				orphanCertificates.add(new OrphanCertificateTokenWrapper((XmlOrphanCertificateToken) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.ORPHAN_CERTIFICATE));
			}
		}
		return orphanCertificates;
	}

	/**
	 * Returns a list of OrphanRevocationTokens
	 * 
	 * @return list of orphan revocations
	 */
	public List<OrphanRevocationTokenWrapper> getTimestampedOrphanRevocations() {
		List<OrphanRevocationTokenWrapper> orphanRevocations = new ArrayList<>();
		
		List<XmlAbstractToken> timestampedObjectsByCategory = getTimestampedObjectsByCategory(TimestampedObjectType.ORPHAN_REVOCATION);
		for (XmlAbstractToken token : timestampedObjectsByCategory) {
			if (token instanceof XmlOrphanRevocationToken) {
				orphanRevocations.add(new OrphanRevocationTokenWrapper((XmlOrphanRevocationToken) token));
			} else {
				throw new IllegalArgumentException(
						String.format("Unexpected token of type [%s] found. Expected : %s", token.getClass(), TimestampedObjectType.ORPHAN_REVOCATION));
			}
		}
		return orphanRevocations;
	}

	@Override
	public byte[] getBinaries() {
		return timestamp.getBase64Encoded();
	}

	/**
	 * Returns digest algorithm and value of the timestamp token binaries, when defined
	 *
	 * @return {@link XmlDigestAlgoAndValue}
	 */
	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return timestamp.getDigestAlgoAndValue();
	}
	
	/* -------- PAdES RFC3161 Specific parameters --------- */

	/**
	 * Returns a PAdES-specific PDF Revision info
	 * NOTE: applicable only for PAdES
	 * 
	 * @return {@link XmlPDFRevision}
	 */
	public XmlPDFRevision getPDFRevision() {
		return timestamp.getPDFRevision();
	}
	
	/**
	 * Indicates if any PDF modifications have been detected
	 *
	 * @return TRUE if any potential PDF modifications have been detected between different revisions, FALSE otherwise
	 */
	public boolean arePdfModificationsDetected() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		return arePdfModificationsDetected(pdfRevision);
	}
	
	/**
	 * Returns a list of PDF annotation overlap concerned pages
	 * 
	 * @return a list of page numbers
	 */
	public List<BigInteger> getPdfAnnotationsOverlapConcernedPages() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		return getPdfAnnotationsOverlapConcernedPages(pdfRevision);
	}
	
	/**
	 * Returns a list of PDF visual difference concerned pages
	 * 
	 * @return a list of page numbers
	 */
	public List<BigInteger> getPdfVisualDifferenceConcernedPages() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		return getPdfVisualDifferenceConcernedPages(pdfRevision);
	}

	/**
	 * Returns a list of pages missing/added to the final revision in a comparison with a signed one
	 * 
	 * @return a list of page numbers
	 */
	public List<BigInteger> getPdfPageDifferenceConcernedPages() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		return getPdfPageDifferenceConcernedPages(pdfRevision);
	}

	/**
	 * Returns a list of changes occurred in a PDF after the current timestamp's revision associated
	 * with a signature/document extension
	 *
	 * @return a list of {@link XmlObjectModification}s
	 */
	public List<XmlObjectModification> getPdfExtensionChanges() {
		return getPdfExtensionChanges(timestamp.getPDFRevision());
	}

	/**
	 * Returns a list of changes occurred in a PDF after the current timestamp's revision associated
	 * with a signature creation, form filling
	 *
	 * @return a list of {@link XmlObjectModification}s
	 */
	public List<XmlObjectModification> getPdfSignatureOrFormFillChanges() {
		return getPdfSignatureOrFormFillChanges(timestamp.getPDFRevision());
	}

	/**
	 * Returns a list of changes occurred in a PDF after the current timestamp's revision associated
	 * with annotation(s) modification
	 *
	 * @return a list of {@link XmlObjectModification}s
	 */
	public List<XmlObjectModification> getPdfAnnotationChanges() {
		return getPdfAnnotationChanges(timestamp.getPDFRevision());
	}

	/**
	 * Returns a list of undefined changes occurred in a PDF after the current timestamp's revision
	 *
	 * @return a list of {@link XmlObjectModification}s
	 */
	public List<XmlObjectModification> getPdfUndefinedChanges() {
		return getPdfUndefinedChanges(timestamp.getPDFRevision());
	}

	/**
	 * This method returns a list of field names modified after the current timestamp's revision
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getModifiedFieldNames() {
		return getModifiedFieldNames(timestamp.getPDFRevision());
	}
	
	/**
	 * Returns the first signature field name
	 * 
	 * @return {@link String} field name
	 */
	public String getFirstFieldName() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			List<XmlPDFSignatureField> fields = pdfRevision.getFields();
			if (fields != null && fields.size() > 0) {
				return fields.iterator().next().getName();
			}
		}
		return null;
	}
	
	/**
	 * Returns a list of signature field names, where the signature is referenced from
	 * 
	 * @return a list of {@link String} signature field names
	 */
	public List<String> getSignatureFieldNames() {
		List<String> names = new ArrayList<>();
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			List<XmlPDFSignatureField> fields = pdfRevision.getFields();
			if (fields != null && fields.size() > 0) {
				for (XmlPDFSignatureField signatureField : fields) {
					names.add(signatureField.getName());
				}
			}
		}
		return names;
	}
	
	/**
	 * Returns a list if Signer Infos (Signer Information Store) from CAdES CMS Signed Data
	 * 
	 * @return list of {@link XmlSignerInfo}s
	 */
	public List<XmlSignerInfo> getSignatureInformationStore() {
		return timestamp.getSignerInformationStore();
	}

	/**
	 * Checks if the tsa field of TSTInfo is present
	 *
	 * @return TRUE if the TSTInfo.tsa is present, FALSE otherwise
	 */
	public boolean isTSAGeneralNamePresent() {
		return timestamp.getTSAGeneralName() != null;
	}

	/**
	 * Get TSA General Name value
	 *
	 * @return {@link String} representing a TSTInfo.tsa field when present, null otherwise
	 */
	public String getTSAGeneralNameValue() {
		if (isTSAGeneralNamePresent()) {
			return timestamp.getTSAGeneralName().getValue();
		}
		return null;
	}

	/**
	 * Checks if the content of TSTInfo.tsa field matches the timestamp's issuer distinguishing name,
	 * without taking order into account
	 *
	 * @return TRUE if the TSTInfo.tsa field value matches the timestamp's issuer name, FALSE otherwise
	 */
	public boolean isTSAGeneralNameMatch() {
		return isTSAGeneralNamePresent() && timestamp.getTSAGeneralName().isContentMatch();
	}

	/**
	 * Checks if the content and the order of TSTInfo.tsa field match the timestamp's issuer distinguishing name
	 *
	 * @return TRUE if the TSTInfo.tsa field value and order match the timestamp's issuer name, FALSE otherwise
	 */
	public boolean isTSAGeneralNameOrderMatch() {
		return isTSAGeneralNamePresent() && timestamp.getTSAGeneralName().isOrderMatch();
	}

	/**
	 * Returns Timestamp's Signature Scopes
	 *
	 * @return a list of {@link XmlSignatureScope}s
	 */
	public List<XmlSignatureScope> getTimestampScopes() {
		return timestamp.getTimestampScopes();
	}

	/**
	 * Returns /Name parameter value
	 *
	 * @return {@link String}
	 */
	public String getSignerName() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getSignerName();
		}
		return null;
	}

	/**
	 * Returns /Type parameter value
	 *
	 * @return {@link String}
	 */
	public String getSignatureDictionaryType() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getType();
		}
		return null;
	}

	/**
	 * Returns /Filter parameter value
	 *
	 * @return {@link String}
	 */
	public String getFilter() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getFilter();
		}
		return null;
	}

	/**
	 * Returns /SubFilter parameter value
	 *
	 * @return {@link String}
	 */
	public String getSubFilter() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getSubFilter();
		}
		return null;
	}

	/**
	 * Returns /ContactInfo parameter value
	 *
	 * @return {@link String}
	 */
	public String getContactInfo() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getContactInfo();
		}
		return null;
	}

	/**
	 * Returns /Reason parameter value
	 *
	 * @return {@link String}
	 */
	public String getReason() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getReason();
		}
		return null;
	}
	
	/**
	 * Returns /ByteRange parameter value
	 *
	 * @return {@link String}
	 */
	public List<BigInteger> getSignatureByteRange() {
		XmlPDFRevision pdfRevision = timestamp.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getSignatureByteRange();
		}
		return Collections.emptyList();
	}

}

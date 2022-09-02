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

import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlByteRange;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCommitmentTypeIndication;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDocMDP;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlObjectModification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFLockDictionary;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFSignatureField;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicyDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSPDocSpecification;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignaturePolicyStore;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerDocumentRepresentations;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerRole;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStructuralValidation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlUserNotice;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.CertificationPermission;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EndorsementType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Contains user-friendly methods to extract information from an {@code XmlSignature}
 *
 */
public class SignatureWrapper extends AbstractTokenProxy {

	/** Wrapped {@code XmlSignature} */
	private final XmlSignature signature;

	/**
	 * Default constructor
	 *
	 * @param signature {@link XmlSignature}
	 */
	public SignatureWrapper(XmlSignature signature) {
		Objects.requireNonNull(signature, "XmlSignature cannot be null!");
		this.signature = signature;
	}

	@Override
	public String getId() {
		return signature.getId();
	}

	/**
	 * Returns the signature document identifier of the signature
	 *
	 * @return {@link String}
	 */
	public String getDAIdentifier() {
		return signature.getDAIdentifier();
	}

	@Override
	public List<XmlDigestMatcher> getDigestMatchers() {
		return signature.getDigestMatchers();
	}

	/**
	 * Returns the message-digest for a CMS signature
	 *
	 * @return {@link XmlDigestMatcher}
	 */
	public XmlDigestMatcher getMessageDigest() {
		List<XmlDigestMatcher> digestMatchers = signature.getDigestMatchers();
		for (XmlDigestMatcher xmlDigestMatcher : digestMatchers) {
			if (DigestMatcherType.MESSAGE_DIGEST == xmlDigestMatcher.getType()) {
				return xmlDigestMatcher;
			}
		}
		return null;
	}

	@Override
	protected XmlBasicSignature getCurrentBasicSignature() {
		return signature.getBasicSignature();
	}

	@Override
	protected List<XmlChainItem> getCurrentCertificateChain() {
		return signature.getCertificateChain();
	}

	@Override
	protected XmlSigningCertificate getCurrentSigningCertificate() {
		return signature.getSigningCertificate();
	}

	/**
	 * Returns FoundCertificatesProxy to access embedded certificates
	 * 
	 * @return {@link FoundCertificatesProxy}
	 */
	@Override
	public FoundCertificatesProxy foundCertificates() {
		return new FoundCertificatesProxy(signature.getFoundCertificates());
	}

	/**
	 * Returns FoundRevocationsProxy to access embedded revocation data
	 * 
	 * @return {@link FoundRevocationsProxy}
	 */
	@Override
	public FoundRevocationsProxy foundRevocations() {
		return new FoundRevocationsProxy(signature.getFoundRevocations());
	}

	/**
	 * Returns a signature filename
	 *
	 * @return {@link String}
	 */
	public String getSignatureFilename() {
		return signature.getSignatureFilename();
	}

	/**
	 * Gets if a structural validation of the signature is valid
	 *
	 * @return TRUE if the structure of the signature is valid, FALSE otherwise
	 */
	public boolean isStructuralValidationValid() {
		return signature.getStructuralValidation() != null && signature.getStructuralValidation().isValid();
	}

	/**
	 * Returns structural validation error messages, when applicable
	 *
	 * @return a list of {@link String} error messages
	 */
	public List<String> getStructuralValidationMessages() {
		XmlStructuralValidation structuralValidation = signature.getStructuralValidation();
		if (structuralValidation != null) {
			return structuralValidation.getMessages();
		}
		return Collections.emptyList();
	}

	/**
	 * Returns the claimed signing time extracted from the signature
	 *
	 * @return {@link Date}
	 */
	public Date getClaimedSigningTime() {
		return signature.getClaimedSigningTime();
	}

	/**
	 * Returns the content type
	 *
	 * @return {@link String}
	 */
	public String getContentType() {
		return signature.getContentType();
	}

	/**
	 * Returns the MimeType
	 *
	 * @return {@link String}
	 */
	public String getMimeType() {
		return signature.getMimeType();
	}

	/**
	 * Returns the content hints string
	 *
	 * @return {@link String}
	 */
	public String getContentHints() {
		return signature.getContentHints();
	}

	/**
	 * Returns the content identifier
	 *
	 * @return {@link String}
	 */
	public String getContentIdentifier() {
		return signature.getContentIdentifier();
	}

	/**
	 * Gets if the current signature counter-signs another signature within the document
	 *
	 * @return TRUE if the signature is counter-signature, FALSE otherwise
	 */
	public boolean isCounterSignature() {
		return signature.isCounterSignature() != null && signature.isCounterSignature();
	}

	/**
	 * Checks if the signature's Id is duplicated within the validating document
	 *
	 * @return TRUE if there is a duplicated signature Id, FALSE otherwise
	 */
	public boolean isSignatureDuplicated() {
		return signature.isDuplicated() != null && signature.isDuplicated();
	}

	/**
	 * Returns Signature Digest Reference
	 *
	 * @return {@link XmlSignatureDigestReference}
	 */
	public XmlSignatureDigestReference getSignatureDigestReference() {
		return signature.getSignatureDigestReference();
	}

	/**
	 * Returns a DataToBeSigned digest
	 *
	 * @return {@link XmlDigestAlgoAndValue}
	 */
	public XmlDigestAlgoAndValue getDataToBeSignedRepresentation() {
		return signature.getDataToBeSignedRepresentation();
	}

	/**
	 * Returns a list of associated timestamps
	 *
	 * @return a list of {@link TimestampWrapper}s
	 */
	public List<TimestampWrapper> getTimestampList() {
		List<TimestampWrapper> tsps = new ArrayList<>();
		List<XmlFoundTimestamp> foundTimestamps = signature.getFoundTimestamps();
		for (XmlFoundTimestamp xmlFoundTimestamp : foundTimestamps) {
			tsps.add(new TimestampWrapper(xmlFoundTimestamp.getTimestamp()));
		}
		return tsps;
	}

	/**
	 * Returns a list of associated timestamps by type
	 *
	 * @param timestampType {@link TimestampType} to get timestamps
	 * @return a list of {@link TimestampWrapper}s
	 */
	public List<TimestampWrapper> getTimestampListByType(final TimestampType timestampType) {
		List<TimestampWrapper> result = new ArrayList<>();
		List<TimestampWrapper> all = getTimestampList();
		for (TimestampWrapper tsp : all) {
			if (timestampType.equals(tsp.getType())) {
				result.add(tsp);
			}
		}
		return result;
	}

	/**
	 * Gets if the signature production place is claimed within the signature
	 *
	 * @return TRUE if the signature production place is present, FALSE otherwise
	 */
	public boolean isSignatureProductionPlacePresent() {
		return signature.getSignatureProductionPlace() != null;
	}

	/**
	 * Returns the signature production place's street address, when present
	 *
	 * @return {@link String}
	 */
	public String getStreetAddress() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getStreetAddress();
		}
		return null;
	}

	/**
	 * Returns the signature production place's city, when present
	 *
	 * @return {@link String}
	 */
	public String getCity() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getCity();
		}
		return null;
	}

	/**
	 * Returns the signature production place's country name, when present
	 *
	 * @return {@link String}
	 */
	public String getCountryName() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getCountryName();
		}
		return null;
	}

	/**
	 * Returns the signature production place's post office box number, when present
	 *
	 * @return {@link String}
	 */
	public String getPostOfficeBoxNumber() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getPostOfficeBoxNumber();
		}
		return null;
	}

	/**
	 * Returns the signature production place's postal code, when present
	 *
	 * @return {@link String}
	 */
	public String getPostalCode() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getPostalCode();
		}
		return null;
	}

	/**
	 * Returns the signature production place's state or province, when present
	 *
	 * @return {@link String}
	 */
	public String getStateOrProvince() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getStateOrProvince();
		}
		return null;
	}

	/**
	 * Returns the signature production place's postal address, when present
	 *
	 * @return {@link String}
	 */
	public List<String> getPostalAddress() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getPostalAddress();
		}
		return Collections.emptyList();
	}

	/**
	 * Returns the signature level (format)
	 *
	 * @return {@link SignatureLevel}
	 */
	public SignatureLevel getSignatureFormat() {
		return signature.getSignatureFormat();
	}

	/**
	 * Returns an error message
	 *
	 * @return {@link String}
	 */
	public String getErrorMessage() {
		return signature.getErrorMessage();
	}

	/**
	 * Gets if a signing certificate has been unambiguously identified
	 *
	 * @return TRUE if the signing certificate has been identifier, FALSE otherwise
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

	/**
	 * Returns the signature policy Id, when present
	 *
	 * @return {@link String}
	 */
	public String getPolicyId() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getId();
		}
		return "";
	}

	/**
	 * Returns if the signature policy's hash should not be compared (zero hash is used)
	 *
	 * @return TRUE if zero hash has been used, FALSE otherwise
	 */
	public boolean isPolicyZeroHash() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null && policy.getDigestAlgoAndValue() != null) {
			return policy.getDigestAlgoAndValue().isZeroHash() != null && policy.getDigestAlgoAndValue().isZeroHash();
		}
		return false;
	}

	/**
	 * Returns the signature policy digest
	 *
	 * @return {@link XmlPolicyDigestAlgoAndValue}
	 */
	public XmlPolicyDigestAlgoAndValue getPolicyDigestAlgoAndValue() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getDigestAlgoAndValue();
		}
		return null;
	}
	
	/**
	 * Checks if a SignaturePolicyStore unsigned property is present
	 * 
	 * @return TRUE if SignaturePolicyStore is present, FALSE otherwise
	 */
	public boolean isPolicyStorePresent() {
		return signature.getSignaturePolicyStore() != null;
	}

	/**
	 * Gets the signature policy store id
	 *
	 * @return {@link String}
	 */
	public String getPolicyStoreId() {
		XmlSignaturePolicyStore policyStore = signature.getSignaturePolicyStore();
		if (policyStore != null) {
			return policyStore.getId();
		}
		return null;
	}

	/**
	 * Gets the signature policy store description
	 *
	 * @return {@link String}
	 */
	public String getPolicyStoreDescription() {
		XmlSignaturePolicyStore policyStore = signature.getSignaturePolicyStore();
		if (policyStore != null) {
			return policyStore.getDescription();
		}
		return null;
	}

	/**
	 * Gets the digest of a signature policy containing within the signature policy store
	 *
	 * @return {@link XmlDigestAlgoAndValue}
	 */
	public XmlDigestAlgoAndValue getPolicyStoreDigestAlgoAndValue() {
		XmlSignaturePolicyStore policyStore = signature.getSignaturePolicyStore();
		if (policyStore != null) {
			return policyStore.getDigestAlgoAndValue();
		}
		return null;
	}

	/**
	 * Returns a signature policy store documentation references
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getPolicyStoreDocumentationReferences() {
		XmlSignaturePolicyStore policyStore = signature.getSignaturePolicyStore();
		if (policyStore != null) {
			return policyStore.getDocumentationReferences();
		}
		return Collections.emptyList();
	}

	/**
	 * Returns a signature policy store local URI
	 *
	 * @return {@link String}
	 */
	public String getPolicyStoreLocalURI() {
		XmlSignaturePolicyStore policyStore = signature.getSignaturePolicyStore();
		if (policyStore != null) {
			return policyStore.getSigPolDocLocalURI();
		}
		return null;
	}

	/**
	 * Gets if the B-level of the signature is valid
	 *
	 * @return TRUE if the B-level of the signature is valid, FALSE otherwise
	 */
	public boolean isBLevelTechnicallyValid() {
		return isSignatureValid();
	}

	/**
	 * Returns if there is the X-Level within the signature
	 *
	 * @return TRUE if there is the X-Level, FALSE otherwise
	 */
	public boolean isThereXLevel() {
		List<TimestampWrapper> timestampLevelX = getTimestampLevelX();
		return timestampLevelX != null && !timestampLevelX.isEmpty();
	}

	/**
	 * Gets if the X-level of the signature is valid
	 *
	 * @return TRUE if the X-level of the signature is valid, FALSE otherwise
	 */
	public boolean isXLevelTechnicallyValid() {
		List<TimestampWrapper> timestamps = getTimestampLevelX();
		return isAtLeastOneTimestampValid(timestamps);
	}

	/**
	 * Returns a list of validation-data-refs-only- and validation-data- time-stamps for the signature
	 *
	 * @return a list of {@link TimestampWrapper}s
	 */
	public List<TimestampWrapper> getTimestampLevelX() {
		List<TimestampWrapper> timestamps = getTimestampListByType(TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
		timestamps.addAll(getTimestampListByType(TimestampType.VALIDATION_DATA_TIMESTAMP));
		return timestamps;
	}

	/**
	 * Returns if there is the A-Level within the signature
	 *
	 * @return TRUE if there is the A-Level, FALSE otherwise
	 */
	public boolean isThereALevel() {
		List<TimestampWrapper> timestamps = getALevelTimestamps();
		return timestamps != null && !timestamps.isEmpty();
	}

	/**
	 * Gets if the A-level of the signature is valid
	 *
	 * @return TRUE if the A-level of the signature is valid, FALSE otherwise
	 */
	public boolean isALevelTechnicallyValid() {
		List<TimestampWrapper> timestamps = getALevelTimestamps();
		return isAtLeastOneTimestampValid(timestamps);
	}

	/**
	 * Returns a list of archive timestamps for the signature
	 *
	 * @return a list of {@link TimestampWrapper}s
	 */
	public List<TimestampWrapper> getALevelTimestamps() {
		List<TimestampWrapper> timestamps = new ArrayList<>(getArchiveTimestamps());
		timestamps.addAll(getDocumentTimestamps(true));
		return timestamps;
	}

	/**
	 * Returns a list of archive timestamps for the signature
	 *
	 * @return a list of {@link TimestampWrapper}s
	 */
	public List<TimestampWrapper> getArchiveTimestamps() {
		return getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
	}

	/**
	 * Returns if there is the T-Level within the signature
	 *
	 * @return TRUE if there is the T-Level, FALSE otherwise
	 */
	public boolean isThereTLevel() {
		List<TimestampWrapper> timestamps = getTLevelTimestamps();
		return timestamps != null && !timestamps.isEmpty();
	}

	/**
	 * Gets if the T-level of the signature is valid
	 *
	 * @return TRUE if the T-level of the signature is valid, FALSE otherwise
	 */
	public boolean isTLevelTechnicallyValid() {
		List<TimestampWrapper> timestamps = getTLevelTimestamps();
		return isAtLeastOneTimestampValid(timestamps);
	}

	/**
	 * Returns a list of signature timestamps for the signature
	 *
	 * @return a list of {@link TimestampWrapper}s
	 */
	public List<TimestampWrapper> getTLevelTimestamps() {
		List<TimestampWrapper> timestamps = new ArrayList<>(getSignatureTimestamps());
		timestamps.addAll(getDocumentTimestamps());
		return timestamps;
	}

	/**
	 * Returns a list of content timestamps of the signature
	 *
	 * @return a list of {@link TimestampWrapper}s
	 */
	public List<TimestampWrapper> getContentTimestamps() {
		List<TimestampWrapper> timestamps = getTimestampListByType(TimestampType.CONTENT_TIMESTAMP);
		timestamps.addAll(getTimestampListByType(TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP));
		timestamps.addAll(getTimestampListByType(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP));
		return timestamps;
	}

	/**
	 * Returns all non-content timestamps
	 *
	 * @return a list of {@link TimestampWrapper}s
	 */
	public List<TimestampWrapper> getAllTimestampsProducedAfterSignatureCreation() {
		List<TimestampWrapper> timestamps = new ArrayList<>();
		for (TimestampType timestampType : TimestampType.values()) {
			if (!timestampType.isContentTimestamp()) {
				timestamps.addAll(getTimestampListByType(timestampType));
			}
		}
		return timestamps;
	}

	/**
	 * Returns all signature timestamps
	 *
	 * @return a list of {@link TimestampWrapper}s
	 */
	public List<TimestampWrapper> getSignatureTimestamps() {
		return getTimestampListByType(TimestampType.SIGNATURE_TIMESTAMP);
	}

	/**
	 * Returns all PDF document timestamps
	 *
	 * @return a list of {@link TimestampWrapper}s
	 */
	public List<TimestampWrapper> getDocumentTimestamps() {
		return getTimestampListByType(TimestampType.DOCUMENT_TIMESTAMP);
	}

	/**
	 * Returns all corresponding VRI timestamps (PAdES only)
	 *
	 * @return a list of {@link TimestampWrapper}s
	 */
	public List<TimestampWrapper> getVRITimestamps() {
		return getTimestampListByType(TimestampType.VRI_TIMESTAMP);
	}

	private List<TimestampWrapper> getDocumentTimestamps(boolean coversLTLevel) {
		List<TimestampWrapper> timestampWrappers = new ArrayList<>();
		for (TimestampWrapper timestampWrapper : getDocumentTimestamps()) {
			if (coversLTLevel == coversLTLevel(timestampWrapper)) {
				timestampWrappers.add(timestampWrapper);
			}
		}
		return  timestampWrappers;
	}

	private boolean coversLTLevel(TimestampWrapper timestampWrapper) {
		if (ArchiveTimestampType.PAdES.equals(timestampWrapper.getArchiveTimestampType())) {
			List<CertificateWrapper> signatureCertificateChain = getCertificateChain();
			List<RelatedRevocationWrapper> relatedRevocationData = foundRevocations().getRelatedRevocationData();
			if (relatedRevocationData == null || relatedRevocationData.isEmpty()) {
				return coversDSSCertificateDataForCertificateChain(timestampWrapper, signatureCertificateChain);
			} else {
				return coversRevocationDataForCertificateChain(timestampWrapper, signatureCertificateChain) &&
						(coversTimestampTokens(timestampWrapper, getTimestampList()) || coversOwnRevocationData(timestampWrapper));
			}
		}
		return false;
	}

	private boolean coversDSSCertificateDataForCertificateChain(TimestampWrapper timestampWrapper,
																List<CertificateWrapper> certificateChain) {
		List<CertificateWrapper> dssCertificates = new ArrayList<>();
		dssCertificates.addAll(foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.DSS_DICTIONARY));
		dssCertificates.addAll(foundCertificates().getRelatedCertificatesByOrigin(CertificateOrigin.VRI_DICTIONARY));
		if (!dssCertificates.isEmpty()) {
			List<CertificateWrapper> timestampedCertificates = timestampWrapper.getTimestampedCertificates();
			for (CertificateWrapper certificateWrapper : certificateChain) {
				if (dssCertificates.contains(certificateWrapper) && timestampedCertificates.contains(certificateWrapper)) {
					return true;
				}
			}
		}
		return false;
	}

	private boolean coversRevocationDataForCertificateChain(TimestampWrapper timestampWrapper,
															List<CertificateWrapper> certificateChain) {
		List<RevocationWrapper> timestampedRevocations = timestampWrapper.getTimestampedRevocations();
		for (CertificateWrapper certificateWrapper : certificateChain) {
			List<CertificateRevocationWrapper> certificateRevocationData = certificateWrapper.getCertificateRevocationData();
			if (certificateRevocationData != null && !certificateRevocationData.isEmpty()) {
				return certificateRevocationData.stream().anyMatch(timestampedRevocations::contains);
			}
		}
		return false;
	}

	private boolean coversTimestampTokens(TimestampWrapper timestamp, List<TimestampWrapper> timestampWrappers) {
		List<TimestampWrapper> timestampedTimestamps = timestamp.getTimestampedTimestamps();
		return timestampedTimestamps != null && timestampWrappers.stream().anyMatch(timestampedTimestamps::contains);
	}

	private boolean coversOwnRevocationData(TimestampWrapper timestampWrapper) {
		CertificateWrapper signingCertificate = timestampWrapper.getSigningCertificate();
		if (signingCertificate.isSelfSigned() || signingCertificate.isTrusted()) {
			return true; // no revocation data required
		}
		return coversRevocationDataForCertificateChain(timestampWrapper, timestampWrapper.getCertificateChain());
	}

	private boolean isAtLeastOneTimestampValid(List<TimestampWrapper> timestampList) {
		if (timestampList != null && !timestampList.isEmpty()) {
			for (final TimestampWrapper timestamp : timestampList) {
				final boolean signatureValid = timestamp.isSignatureValid();
				final XmlDigestMatcher messageImprint = timestamp.getMessageImprint();
				final boolean messageImprintIntact = messageImprint.isDataFound() && messageImprint.isDataIntact();
				if (signatureValid && messageImprintIntact) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Returns a list of timestamp IDs
	 *
	 * @return a list of {@link String} IDs
	 */
	public List<String> getTimestampIdsList() {
		List<String> result = new ArrayList<>();
		List<TimestampWrapper> timestamps = getTimestampList();
		if (timestamps != null) {
			for (TimestampWrapper tsp : timestamps) {
				result.add(tsp.getId());
			}
		}
		return result;
	}

	/**
	 * This method returns a reference extracted from a 'kid' (key identifier) header (used in JAdES)
	 *
	 * @return {@link CertificateRefWrapper}
	 */
	public CertificateRefWrapper getKeyIdentifierReference() {
		List<CertificateRefWrapper> certificateRefs = new ArrayList<>();
		certificateRefs.addAll(foundCertificates().getRelatedCertificateRefsByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER));
		certificateRefs.addAll(foundCertificates().getOrphanCertificateRefsByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER));
		if (!certificateRefs.isEmpty()) {
			// only one shall be present
			return certificateRefs.iterator().next();
		}
		return null;
	}

	/**
	 * Returns a master-signature in case of a counter-signature
	 *
	 * @return {@link SignatureWrapper}
	 */
	public SignatureWrapper getParent() {
		XmlSignature parent = signature.getParent();
		if (parent != null) {
			return new SignatureWrapper(parent);
		}
		return null;
	}

	/**
	 * Returns Signature Scopes
	 *
	 * @return a list of {@link XmlSignatureScope}s
	 */
	public List<XmlSignatureScope> getSignatureScopes() {
		return signature.getSignatureScopes();
	}

	/**
	 * Returns list of all found SignerRoles
	 *
	 * @return list of {@link XmlSignerRole}s
	 */
	public List<XmlSignerRole> getSignerRoles() {
		return signature.getSignerRole();
	}

	/**
	 * Returns list of found ClaimedRoles
	 *
	 * @return list of {@link XmlSignerRole}s
	 */
	public List<XmlSignerRole> getClaimedRoles() {
		return getSignerRolesByCategory(EndorsementType.CLAIMED);
	}

	/**
	 * Returns list of found CertifiedRoles
	 *
	 * @return list of {@link XmlSignerRole}s
	 */
	public List<XmlSignerRole> getCertifiedRoles() {
		return getSignerRolesByCategory(EndorsementType.CERTIFIED);
	}
	
	/**
	 * Returns list of all found SignedAssertions
	 * 
	 * @return list of {@link XmlSignerRole}s
	 */
	public List<XmlSignerRole> getSignedAssertions() {
		return getSignerRolesByCategory(EndorsementType.SIGNED);
	}

	/**
	 * Returns a list of {@code String}s describing the role for the given
	 * {@code listOfSignerRoles}
	 * 
	 * @param listOfSignerRoles - list of {@link XmlSignerRole} to get string role
	 *                          details from
	 * @return list of role details
	 */
	public List<String> getSignerRoleDetails(List<XmlSignerRole> listOfSignerRoles) {
		List<String> roles = new ArrayList<>();
		for (XmlSignerRole xmlSignerRole : listOfSignerRoles) {
			roles.add(xmlSignerRole.getRole());
		}
		return roles;
	}
	
	private List<XmlSignerRole> getSignerRolesByCategory(EndorsementType category) {
		List<XmlSignerRole> roles = new ArrayList<>();
		for (XmlSignerRole xmlSignerRole : getSignerRoles()) {
			if (category.equals(xmlSignerRole.getCategory())) {
				roles.add(xmlSignerRole);
			}
		}
		return roles;
	}

	/**
	 * Returns a list of commitment type indications
	 *
	 * @return a lust of {@link XmlCommitmentTypeIndication}s
	 */
	public List<XmlCommitmentTypeIndication> getCommitmentTypeIndications() {
		List<XmlCommitmentTypeIndication> commitmentTypeIndications = signature.getCommitmentTypeIndications();
		if (commitmentTypeIndications != null) {
			return commitmentTypeIndications;
		}
		return Collections.emptyList();
	}

	/**
	 * Checks if a SignaturePolicyIdentifier is present
	 * 
	 * @return TRUE if a SignaturePolicyIdentifier is found, FALSE otherwise
	 */
	public boolean isPolicyPresent() {
		return signature.getPolicy() != null;
	}

	/**
	 * Returns an error string occurred during a SignaturePolicy proceeding, when applicable
	 * 
	 * @return {@link String} representing a policy validation error message, empty when no errors found
	 */
	public String getPolicyProcessingError() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getProcessingError();
		}
		return "";
	}
	
	/**
	 * Returns XMLPolicy description if it is not empty
	 *
	 * @return {@link String}
	 */
	public String getPolicyDescription() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null && policy.getDescription() != null) {
			return policy.getDescription();
		}
		return "";
	}
	
	/**
	 * Returns DocumentationReferences defined for the signature policy
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getPolicyDocumentationReferences() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null && policy.getDocumentationReferences() != null) {
			return policy.getDocumentationReferences();
		}
		return Collections.emptyList();
	}
	
	/**
	 * Returns a list of Policy transformations
	 * NOTE: used only for XAdES signatures
	 * 
	 * @return a list of {@link String}s
	 */
	public List<String> getPolicyTransforms() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null && policy.getTransformations() != null) {
			return policy.getTransformations();
		}
		return Collections.emptyList();
	}

	/**
	 * Returns the signature policy url
	 *
	 * @return {@link String}
	 */
	public String getPolicyUrl() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getUrl();
		}
		return "";
	}

	/**
	 * Returns the policy UserNotice
	 *
	 * @return {@link XmlUserNotice}
	 */
	public XmlUserNotice getPolicyUserNotice() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getUserNotice();
		}
		return null;
	}

	/**
	 * Returns the signature policy document specification
	 *
	 * @return {@link XmlSPDocSpecification}
	 */
	public XmlSPDocSpecification getPolicyDocSpecification() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getDocSpecification();
		}
		return null;
	}

	/**
	 * Gets if the signature policy is ASN.1 processable
	 *
	 * @return TRUE if the signature policy is ASN.1, FALSE otherwise
	 */
	public boolean isPolicyAsn1Processable() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.isAsn1Processable() != null && policy.isAsn1Processable();
		}
		return false;
	}

	/**
	 * Gets if the signature policy has been found
	 *
	 * @return TRUE if the signature policy has been found, FALSE otherwise
	 */
	public boolean isPolicyIdentified() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.isIdentified() != null && policy.isIdentified();
		}
		return false;
	}

	/**
	 * Gets if the signature policy digest validation succeeds
	 *
	 * @return TRUE if the signature policy digest are valid, FALSE otherwise
	 */
	public boolean isPolicyDigestValid() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null && policy.getDigestAlgoAndValue() != null) {
			return policy.getDigestAlgoAndValue().isMatch() != null && policy.getDigestAlgoAndValue().isMatch();
		}
		return false;
	}

	/**
	 * Gets if the validated signature policy algorithm match
	 *
	 * @return TRUE if the signature policy digest algorithms match, FALSE otherwise
	 */
	public boolean isPolicyDigestAlgorithmsEqual() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null && policy.getDigestAlgoAndValue() != null) {
			return policy.getDigestAlgoAndValue().isDigestAlgorithmsEqual() != null
					&& policy.getDigestAlgoAndValue().isDigestAlgorithmsEqual();
		}
		return false;
	}
	
	/**
	 * Returns a PAdES-specific PDF Revision info
	 * NOTE: applicable only for PAdES
	 * 
	 * @return {@link XmlPDFRevision}
	 */
	public XmlPDFRevision getPDFRevision() {
		return signature.getPDFRevision();
	}
	
	/**
	 * Checks if any visual modifications detected in the PDF
	 * 
	 * @return TRUE if modifications detected in a PDF, FALSE otherwise
	 */
	public boolean arePdfModificationsDetected() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		return arePdfModificationsDetected(pdfRevision);
	}
	
	/**
	 * Returns a list of PDF annotation overlap concerned pages
	 * 
	 * @return a list of page numbers
	 */
	public List<BigInteger> getPdfAnnotationsOverlapConcernedPages() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		return getPdfAnnotationsOverlapConcernedPages(pdfRevision);
	}

	/**
	 * Returns a list of PDF visual difference concerned pages
	 * 
	 * @return a list of page numbers
	 */
	public List<BigInteger> getPdfVisualDifferenceConcernedPages() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		return getPdfVisualDifferenceConcernedPages(pdfRevision);
	}

	/**
	 * Returns a list of pages missing/added to the final revision in a comparison with a signed one
	 * 
	 * @return a list of page numbers
	 */
	public List<BigInteger> getPdfPageDifferenceConcernedPages() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		return getPdfPageDifferenceConcernedPages(pdfRevision);
	}

	/**
	 * This method checks whether object modifications are present after the current PDF revisions
	 *
	 * @return TRUE if PDF has been modified, FALSE otherwise
	 */
	public boolean arePdfObjectModificationsDetected() {
		return getPdfObjectModifications(signature.getPDFRevision()) != null;
	}

	/**
	 * Returns a list of changes occurred in a PDF after the current signature's revision associated
	 * with a signature/document extension
	 *
	 * @return a list of {@link XmlObjectModification}s
	 */
	public List<XmlObjectModification> getPdfExtensionChanges() {
		return getPdfExtensionChanges(signature.getPDFRevision());
	}

	/**
	 * Returns a list of changes occurred in a PDF after the current signature's revision associated
	 * with a signature creation, form filling
	 *
	 * @return a list of {@link XmlObjectModification}s
	 */
	public List<XmlObjectModification> getPdfSignatureOrFormFillChanges() {
		return getPdfSignatureOrFormFillChanges(signature.getPDFRevision());
	}

	/**
	 * Returns a list of changes occurred in a PDF after the current signature's revision associated
	 * with annotation(s) modification
	 *
	 * @return a list of {@link XmlObjectModification}s
	 */
	public List<XmlObjectModification> getPdfAnnotationChanges() {
		return getPdfAnnotationChanges(signature.getPDFRevision());
	}

	/**
	 * Returns a list of undefined changes occurred in a PDF after the current signature's revision
	 *
	 * @return a list of {@link XmlObjectModification}s
	 */
	public List<XmlObjectModification> getPdfUndefinedChanges() {
		return getPdfUndefinedChanges(signature.getPDFRevision());
	}

	/**
	 * This method returns a list of field names modified after the current signature's revision
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getModifiedFieldNames() {
		return getModifiedFieldNames(signature.getPDFRevision());
	}
	
	/**
	 * Returns the first signature field name
	 * 
	 * @return {@link String} field name
	 */
	public String getFirstFieldName() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			List<XmlPDFSignatureField> fields = pdfRevision.getFields();
			if (fields != null && !fields.isEmpty()) {
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
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			List<XmlPDFSignatureField> fields = pdfRevision.getFields();
			if (fields != null && !fields.isEmpty()) {
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
		return signature.getSignerInformationStore();
	}

	/**
	 * Returns the signer's name
	 *
	 * @return {@link String}
	 */
	public String getSignerName() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getSignerName();
		}
		return null;
	}

	/**
	 * Returns the PDF signature dictionary /Type value
	 *
	 * @return {@link String}
	 */
	public String getSignatureDictionaryType() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getType();
		}
		return null;
	}

	/**
	 * Returns the PDF signature dictionary /Filter value
	 *
	 * @return {@link String}
	 */
	public String getFilter() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getFilter();
		}
		return null;
	}

	/**
	 * Returns the PDF signature dictionary /SubFilter value
	 *
	 * @return {@link String}
	 */
	public String getSubFilter() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getSubFilter();
		}
		return null;
	}

	/**
	 * Returns the PDF signature dictionary /ContactInfo value
	 *
	 * @return {@link String}
	 */
	public String getContactInfo() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getContactInfo();
		}
		return null;
	}

	/**
	 * Returns the PDF signature dictionary /Location value
	 *
	 * @return {@link String}
	 */
	public String getLocation() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getLocation();
		}
		return null;
	}

	/**
	 * Returns the PDF signature dictionary /Reason value
	 *
	 * @return {@link String}
	 */
	public String getReason() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getReason();
		}
		return null;
	}

	/**
	 * Returns the PDF signature dictionary /ByteRange value
	 *
	 * @return byte range
	 */
	public List<BigInteger> getSignatureByteRange() {
		XmlByteRange byteRange = getXmlByteRange();
		if (byteRange != null) {
			return byteRange.getValue();
		}
		return Collections.emptyList();
	}

	/**
	 * This method returns whether the PDF signature dictionary /ByteRange is found and valid
	 *
	 * @return TRUE if the /ByteRange is valid, FALSE otherwise
	 */
	public boolean isSignatureByteRangeValid() {
		XmlByteRange byteRange = getXmlByteRange();
		if (byteRange != null) {
			return byteRange.isValid();
		}
		return false;
	}

	private XmlByteRange getXmlByteRange() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null && pdfRevision.getPDFSignatureDictionary() != null) {
			return pdfRevision.getPDFSignatureDictionary().getSignatureByteRange();
		}
		return null;
	}

	/**
	 * Returns a {@code CertificationPermission} value of a /DocMDP dictionary, when present
	 *
	 * @return {@link CertificationPermission}
	 */
	public CertificationPermission getDocMDPPermissions() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			XmlDocMDP docMDP = pdfRevision.getPDFSignatureDictionary().getDocMDP();
			if (docMDP != null) {
				return docMDP.getPermissions();
			}
		}
		return null;
	}

	/**
	 * Returns a /FieldMDP dictionary content, when present
	 *
	 * @return {@link XmlPDFLockDictionary}
	 */
	public XmlPDFLockDictionary getFieldMDP() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getFieldMDP();
		}
		return null;
	}

	/**
	 * Returns a /SigFieldLock dictionary, when present
	 *
	 * @return {@link XmlPDFLockDictionary}
	 */
	public XmlPDFLockDictionary getSigFieldLock() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			List<XmlPDFSignatureField> fields = pdfRevision.getFields();
			for (XmlPDFSignatureField field : fields) {
				XmlPDFLockDictionary sigFieldLock = field.getSigFieldLock();
				if (sigFieldLock != null) {
					return sigFieldLock;
				}
			}
		}
		return null;
	}

	/**
	 * Returns time of /VRI dictionary creation, when 'TU' attribute is present (PAdES only)
	 *
	 * @return {@link Date}
	 */
	public Date getVRIDictionaryCreationTime() {
		return signature.getVRIDictionaryCreationTime();
	}

	/**
	 * Gets the SignatureValue
	 *
	 * @return binaries
	 */
	public byte[] getSignatureValue() {
		return signature.getSignatureValue();
	}

	/**
	 * Gets if the signature is a document hash only
	 *
	 * @return TRUE if the signature is a document hash only, FALSE otherwise
	 */
	public boolean isDocHashOnly() {
		XmlSignerDocumentRepresentations signerDocumentRepresentation = signature.getSignerDocumentRepresentations();
		if (signerDocumentRepresentation != null) {
			return signerDocumentRepresentation.isDocHashOnly();
		}
		return false;
	}

	/**
	 * Gets if the signature is a hash only
	 *
	 * @return TRUE if the signature is a hash only, FALSE otherwise
	 */
	public boolean isHashOnly() {
		XmlSignerDocumentRepresentations signerDocumentRepresentation = signature.getSignerDocumentRepresentations();
		if (signerDocumentRepresentation != null) {
			return signerDocumentRepresentation.isHashOnly();
		}
		return false;
	}

	@Override
	public byte[] getBinaries() {
		return signature.getSignatureValue();
	}

}

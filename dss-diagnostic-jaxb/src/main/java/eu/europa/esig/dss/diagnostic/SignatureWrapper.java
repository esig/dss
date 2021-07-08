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
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCommitmentTypeIndication;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicyDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignaturePolicyStore;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerDocumentRepresentations;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerRole;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStructuralValidation;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
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

public class SignatureWrapper extends AbstractTokenProxy {

	private final XmlSignature signature;
	
	public SignatureWrapper(XmlSignature signature) {
		Objects.requireNonNull(signature, "XmlSignature cannot be null!");
		this.signature = signature;
	}

	@Override
	public String getId() {
		return signature.getId();
	}

	public String getDAIdentifier() {
		return signature.getDAIdentifier();
	}

	@Override
	public List<XmlDigestMatcher> getDigestMatchers() {
		return signature.getDigestMatchers();
	}

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

	public String getSignatureFilename() {
		return signature.getSignatureFilename();
	}

	public boolean isStructuralValidationValid() {
		return signature.getStructuralValidation() != null && signature.getStructuralValidation().isValid();
	}

	public List<String> getStructuralValidationMessages() {
		XmlStructuralValidation structuralValidation = signature.getStructuralValidation();
		if (structuralValidation != null) {
			return structuralValidation.getMessages();
		}
		return Collections.emptyList();
	}

	public Date getClaimedSigningTime() {
		return signature.getClaimedSigningTime();
	}

	public String getContentType() {
		return signature.getContentType();
	}

	public String getMimeType() {
		return signature.getMimeType();
	}

	public String getContentHints() {
		return signature.getContentHints();
	}

	public String getContentIdentifier() {
		return signature.getContentIdentifier();
	}

	public boolean isCounterSignature() {
		return signature.isCounterSignature() != null && signature.isCounterSignature();
	}
	
	public boolean isSignatureDuplicated() {
		return signature.isDuplicated() != null && signature.isDuplicated();
	}
	
	public XmlSignatureDigestReference getSignatureDigestReference() {
		return signature.getSignatureDigestReference();
	}
	
	public XmlDigestAlgoAndValue getDataToBeSignedRepresentation() {
		return signature.getDataToBeSignedRepresentation();
	}

	public List<TimestampWrapper> getTimestampList() {
		List<TimestampWrapper> tsps = new ArrayList<>();
		List<XmlFoundTimestamp> foundTimestamps = signature.getFoundTimestamps();
		for (XmlFoundTimestamp xmlFoundTimestamp : foundTimestamps) {
			tsps.add(new TimestampWrapper(xmlFoundTimestamp.getTimestamp()));
		}
		return tsps;
	}

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

	public boolean isSignatureProductionPlacePresent() {
		return signature.getSignatureProductionPlace() != null;
	}

	public String getStreetAddress() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getStreetAddress();
		}
		return null;
	}

	public String getCity() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getCity();
		}
		return null;
	}

	public String getCountryName() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getCountryName();
		}
		return null;
	}

	public String getPostOfficeBoxNumber() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getPostOfficeBoxNumber();
		}
		return null;
	}

	public String getPostalCode() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getPostalCode();
		}
		return null;
	}

	public String getStateOrProvince() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getStateOrProvince();
		}
		return null;
	}

	public List<String> getPostalAddress() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getPostalAddress();
		}
		return Collections.emptyList();
	}

	public SignatureLevel getSignatureFormat() {
		return signature.getSignatureFormat();
	}

	public String getErrorMessage() {
		return signature.getErrorMessage();
	}

	public boolean isSigningCertificateIdentified() {
		CertificateWrapper signingCertificate = getSigningCertificate();
		CertificateRefWrapper signingCertificateReference = getSigningCertificateReference();
		if (signingCertificate != null && signingCertificateReference != null) {
			return signingCertificateReference.isDigestValueMatch() && 
					(!signingCertificateReference.isIssuerSerialPresent() || signingCertificateReference.isIssuerSerialMatch());
		}
		return false;
	}

	public String getPolicyId() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getId();
		}
		return "";
	}

	public boolean isPolicyZeroHash() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null && policy.getDigestAlgoAndValue() != null) {
			return policy.getDigestAlgoAndValue().isZeroHash() != null && policy.getDigestAlgoAndValue().isZeroHash();
		}
		return false;
	}

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
	
	public String getPolicyStoreId() {
		XmlSignaturePolicyStore policyStore = signature.getSignaturePolicyStore();
		if (policyStore != null) {
			return policyStore.getId();
		}
		return null;
	}
	
	public String getPolicyStoreDescription() {
		XmlSignaturePolicyStore policyStore = signature.getSignaturePolicyStore();
		if (policyStore != null) {
			return policyStore.getDescription();
		}
		return null;
	}
	
	public XmlDigestAlgoAndValue getPolicyStoreDigestAlgoAndValue() {
		XmlSignaturePolicyStore policyStore = signature.getSignaturePolicyStore();
		if (policyStore != null) {
			return policyStore.getDigestAlgoAndValue();
		}
		return null;
	}
	
	public List<String> getPolicyStoreDocumentationReferences() {
		XmlSignaturePolicyStore policyStore = signature.getSignaturePolicyStore();
		if (policyStore != null) {
			return policyStore.getDocumentationReferences();
		}
		return Collections.emptyList();
	}

	public boolean isBLevelTechnicallyValid() {
		return isSignatureValid();
	}

	public boolean isThereXLevel() {
		List<TimestampWrapper> timestampLevelX = getTimestampLevelX();
		return timestampLevelX != null && timestampLevelX.size() > 0;
	}

	public boolean isXLevelTechnicallyValid() {
		List<TimestampWrapper> timestamps = getTimestampLevelX();
		return isAtLeastOneTimestampValid(timestamps);
	}

	public List<TimestampWrapper> getTimestampLevelX() {
		List<TimestampWrapper> timestamps = getTimestampListByType(TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
		timestamps.addAll(getTimestampListByType(TimestampType.VALIDATION_DATA_TIMESTAMP));
		return timestamps;
	}

	public boolean isThereALevel() {
		List<TimestampWrapper> timestamps = getALevelTimestamps();
		return timestamps != null && timestamps.size() > 0;
	}

	public boolean isALevelTechnicallyValid() {
		List<TimestampWrapper> timestamps = getALevelTimestamps();
		return isAtLeastOneTimestampValid(timestamps);
	}

	public List<TimestampWrapper> getALevelTimestamps() {
		List<TimestampWrapper> timestamps = new ArrayList<>(getArchiveTimestamps());
		timestamps.addAll(getDocumentTimestamps(true));
		return timestamps;
	}

	public List<TimestampWrapper> getArchiveTimestamps() {
		return getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
	}

	public boolean isThereTLevel() {
		List<TimestampWrapper> timestamps = getTLevelTimestamps();
		return timestamps != null && timestamps.size() > 0;
	}

	public boolean isTLevelTechnicallyValid() {
		List<TimestampWrapper> timestamps = getTLevelTimestamps();
		return isAtLeastOneTimestampValid(timestamps);
	}

	public List<TimestampWrapper> getTLevelTimestamps() {
		List<TimestampWrapper> timestamps = new ArrayList<>(getSignatureTimestamps());
		timestamps.addAll(getDocumentTimestamps());
		return timestamps;
	}

	public List<TimestampWrapper> getContentTimestamps() {
		List<TimestampWrapper> timestamps = getTimestampListByType(TimestampType.CONTENT_TIMESTAMP);
		timestamps.addAll(getTimestampListByType(TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP));
		timestamps.addAll(getTimestampListByType(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP));
		return timestamps;
	}

	public List<TimestampWrapper> getAllTimestampsProducedAfterSignatureCreation() {
		List<TimestampWrapper> timestamps = new ArrayList<>();
		for (TimestampType timestampType : TimestampType.values()) {
			if (!timestampType.isContentTimestamp()) {
				timestamps.addAll(getTimestampListByType(timestampType));
			}
		}
		return timestamps;
	}

	public List<TimestampWrapper> getSignatureTimestamps() {
		return getTimestampListByType(TimestampType.SIGNATURE_TIMESTAMP);
	}

	public List<TimestampWrapper> getDocumentTimestamps() {
		return getTimestampListByType(TimestampType.DOCUMENT_TIMESTAMP);
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
		return ArchiveTimestampType.PAdES.equals(timestampWrapper.getArchiveTimestampType());
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

	public SignatureWrapper getParent() {
		XmlSignature parent = signature.getParent();
		if (parent != null) {
			return new SignatureWrapper(parent);
		}
		return null;
	}

	public List<XmlSignatureScope> getSignatureScopes() {
		return signature.getSignatureScopes();
	}

	/**
	 * Returns list of all found SignerRoles
	 * @return list of {@link XmlSignerRole}s
	 */
	public List<XmlSignerRole> getSignerRoles() {
		return signature.getSignerRole();
	}

	/**
	 * Returns list of found ClaimedRoles
	 * @return list of {@link XmlSignerRole}s
	 */
	public List<XmlSignerRole> getClaimedRoles() {
		return getSignerRolesByCategory(EndorsementType.CLAIMED);
	}

	/**
	 * Returns list of found CertifiedRoles
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

	public String getPolicyNotice() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getNotice();
		}
		return "";
	}

	public String getPolicyUrl() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getUrl();
		}
		return "";
	}

	public String getPolicyDocSpecification() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getDocSpecification();
		}
		return "";
	}

	public boolean isPolicyAsn1Processable() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.isAsn1Processable() != null && policy.isAsn1Processable();
		}
		return false;
	}

	public boolean isPolicyIdentified() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.isIdentified() != null && policy.isIdentified();
		}
		return false;
	}

	public boolean isPolicyDigestValid() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null && policy.getDigestAlgoAndValue() != null) {
			return policy.getDigestAlgoAndValue().isMatch() != null && policy.getDigestAlgoAndValue().isMatch();
		}
		return false;
	}

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
	 * Returns the first signature field name
	 * 
	 * @return {@link String} field name
	 */
	public String getFirstFieldName() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getSignatureFieldName().get(0);
		}
		return null;
	}
	
	/**
	 * Returns a list of signature field names, where the signature is referenced from
	 * 
	 * @return a list of {@link String} signature field names
	 */
	public List<String> getSignatureFieldNames() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getSignatureFieldName();
		}
		return Collections.emptyList();
	}
	
	/**
	 * Returns a list if Signer Infos (Signer Information Store) from CAdES CMS Signed Data
	 * 
	 * @return list of {@link XmlSignerInfo}s
	 */
	public List<XmlSignerInfo> getSignatureInformationStore() {
		return signature.getSignerInformationStore();
	}

	public String getSignerName() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getSignerName();
		}
		return null;
	}

	public String getSignatureDictionaryType() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getType();
		}
		return null;
	}

	public String getFilter() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getFilter();
		}
		return null;
	}

	public String getSubFilter() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getSubFilter();
		}
		return null;
	}

	public String getContactInfo() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getContactInfo();
		}
		return null;
	}

	public String getLocation() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getLocation();
		}
		return null;
	}

	public String getReason() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getReason();
		}
		return null;
	}
	
	public List<BigInteger> getSignatureByteRange() {
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getPDFSignatureDictionary().getSignatureByteRange();
		}
		return Collections.emptyList();
	}
	
	public byte[] getSignatureValue() {
		return signature.getSignatureValue();
	}
	
	public boolean isDocHashOnly() {
		XmlSignerDocumentRepresentations signerDocumentRepresentation = signature.getSignerDocumentRepresentations();
		if (signerDocumentRepresentation != null) {
			return signerDocumentRepresentation.isDocHashOnly();
		}
		return false;
	}
	
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

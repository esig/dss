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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundCertificates;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlFoundTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPDFRevision;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRelatedRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocationRef;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureDigestReference;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerDocumentRepresentations;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerRole;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlStructuralValidation;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EndorsementType;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampLocation;
import eu.europa.esig.dss.enumerations.TimestampType;

public class SignatureWrapper extends AbstractTokenProxy {

	private final XmlSignature signature;

	public SignatureWrapper(XmlSignature signature) {
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

	public String getSignatureFilename() {
		return signature.getSignatureFilename();
	}

	public boolean isStructuralValidationValid() {
		return (signature.getStructuralValidation() != null) && signature.getStructuralValidation().isValid();
	}

	public String getStructuralValidationMessage() {
		XmlStructuralValidation structuralValidation = signature.getStructuralValidation();
		if (structuralValidation != null) {
			return structuralValidation.getMessage();
		}
		return "";
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

	public List<TimestampWrapper> getTimestampList() {
		List<TimestampWrapper> tsps = new ArrayList<TimestampWrapper>();
		List<XmlFoundTimestamp> foundTimestamps = signature.getFoundTimestamps();
		for (XmlFoundTimestamp xmlFoundTimestamp : foundTimestamps) {
			tsps.add(new TimestampWrapper(xmlFoundTimestamp.getTimestamp()));
		}
		return tsps;
	}

	public List<TimestampWrapper> getTimestampListByType(final TimestampType timestampType) {
		List<TimestampWrapper> result = new ArrayList<TimestampWrapper>();
		List<TimestampWrapper> all = getTimestampList();
		for (TimestampWrapper tsp : all) {
			if (timestampType.equals(tsp.getType())) {
				result.add(tsp);
			}
		}
		return result;
	}
	
	public List<TimestampWrapper> getTimestampListByLocation(TimestampLocation timestampLocation) {
		List<TimestampWrapper> tsps = new ArrayList<TimestampWrapper>();
		List<XmlFoundTimestamp> foundTimestamps = signature.getFoundTimestamps();
		for (XmlFoundTimestamp xmlFoundTimestamp : foundTimestamps) {
			if (xmlFoundTimestamp.getLocation() != null && 
					xmlFoundTimestamp.getLocation().name().equals(timestampLocation.name())) {
				tsps.add(new TimestampWrapper(xmlFoundTimestamp.getTimestamp()));
			}
		}
		return tsps;
	}

	public boolean isSignatureProductionPlacePresent() {
		return signature.getSignatureProductionPlace() != null;
	}

	public String getAddress() {
		if (isSignatureProductionPlacePresent()) {
			return signature.getSignatureProductionPlace().getAddress();
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

	public SignatureLevel getSignatureFormat() {
		return signature.getSignatureFormat();
	}

	public String getErrorMessage() {
		return signature.getErrorMessage();
	}

	public boolean isSigningCertificateIdentified() {
		XmlSigningCertificate signingCertificate = signature.getSigningCertificate();
		if (signingCertificate != null) {
			return signingCertificate.isDigestValueMatch() && signingCertificate.isIssuerSerialMatch();
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

	public boolean isZeroHashPolicy() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.isZeroHash() != null && policy.isZeroHash();
		}
		return false;
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
		return isTimestampValid(timestamps);
	}

	public List<TimestampWrapper> getTimestampLevelX() {
		List<TimestampWrapper> timestamps = getTimestampListByType(TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
		timestamps.addAll(getTimestampListByType(TimestampType.VALIDATION_DATA_TIMESTAMP));
		return timestamps;
	}

	public boolean isThereALevel() {
		List<TimestampWrapper> timestampList = getArchiveTimestamps();
		return timestampList != null && timestampList.size() > 0;
	}

	public boolean isALevelTechnicallyValid() {
		List<TimestampWrapper> timestampList = getArchiveTimestamps();
		return isTimestampValid(timestampList);
	}

	public List<TimestampWrapper> getArchiveTimestamps() {
		return getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
	}

	public boolean isThereTLevel() {
		List<TimestampWrapper> timestamps = getSignatureTimestamps();
		return timestamps != null && timestamps.size() > 0;
	}

	public boolean isTLevelTechnicallyValid() {
		List<TimestampWrapper> timestampList = getSignatureTimestamps();
		return isTimestampValid(timestampList);
	}

	public List<TimestampWrapper> getContentTimestamps() {
		List<TimestampWrapper> timestamps = getTimestampListByType(TimestampType.CONTENT_TIMESTAMP);
		timestamps.addAll(getTimestampListByType(TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP));
		timestamps.addAll(getTimestampListByType(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP));
		return timestamps;
	}

	public List<TimestampWrapper> getSignatureTimestamps() {
		return getTimestampListByType(TimestampType.SIGNATURE_TIMESTAMP);
	}

	private boolean isTimestampValid(List<TimestampWrapper> timestampList) {
		for (final TimestampWrapper timestamp : timestampList) {
			final boolean signatureValid = timestamp.isSignatureValid();
			final XmlDigestMatcher messageImprint = timestamp.getMessageImprint();
			final boolean messageImprintIntact = messageImprint.isDataFound() && messageImprint.isDataIntact();
			if (signatureValid && messageImprintIntact) {
				return true;
			}
		}
		return false;
	}

	public List<String> getTimestampIdsList() {
		List<String> result = new ArrayList<String>();
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
	 * Returns a list of {@code String}s describing the role for the given {@code listOfSignerRoles}
	 * 
	 * @param listOfSignerRoles - list of {@link XmlSignerRole} to get string role details from
	 * @return list of role details
	 */
	public List<String> getSignerRoleDetails(List<XmlSignerRole> listOfSignerRoles) {
		List<String> roles = new ArrayList<String>();
		for (XmlSignerRole xmlSignerRole : listOfSignerRoles) {
			roles.add(xmlSignerRole.getRole());
		}
		return roles;
	}
	
	private List<XmlSignerRole> getSignerRolesByCategory(EndorsementType category) {
		List<XmlSignerRole> roles = new ArrayList<XmlSignerRole>();
		for (XmlSignerRole xmlSignerRole : getSignerRoles()) {
			if (category.equals(xmlSignerRole.getCategory())) {
				roles.add(xmlSignerRole);
			}
		}
		return roles;
	}

	public List<String> getCommitmentTypeIdentifiers() {
		List<String> commitmentTypeIndications = signature.getCommitmentTypeIndication();
		if (commitmentTypeIndications != null) {
			return commitmentTypeIndications;
		}
		return Collections.emptyList();
	}

	public boolean isPolicyPresent() {
		return signature.getPolicy() != null;
	}

	public String getPolicyProcessingError() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getProcessingError();
		}
		return "";
	}

	public boolean getPolicyStatus() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.isStatus();
		}
		return false;
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

	public boolean isPolicyStatus() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.isStatus() != null && policy.isStatus();
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
		XmlPDFRevision pdfRevision = signature.getPDFRevision();
		if (pdfRevision != null) {
			return pdfRevision.getSignerInformationStore();
		}
		return Collections.emptyList();
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
	
	public List<XmlFoundCertificate> getAllFoundCertificates() {
		List<XmlFoundCertificate> foundCertificates = new ArrayList<XmlFoundCertificate>();
		for (XmlFoundCertificate foundCertificate : getRelatedCertificates()) {
			foundCertificates.add(foundCertificate);
		}
		for (XmlFoundCertificate foundCertificate : getOrphanCertificates()) {
			foundCertificates.add(foundCertificate);
		}
		return foundCertificates;
	}
	
	public List<XmlRelatedCertificate> getRelatedCertificates() {
		return signature.getFoundCertificates().getRelatedCertificates();
	}
	
	public List<XmlOrphanCertificate> getOrphanCertificates() {
		return signature.getFoundCertificates().getOrphanCertificates();
	}
	
	public List<XmlFoundRevocation> getAllFoundRevocations() {
		List<XmlFoundRevocation> foundRevocations = new ArrayList<XmlFoundRevocation>();
		foundRevocations.addAll(getRelatedRevocations());
		foundRevocations.addAll(getOrphanRevocations());
		return foundRevocations;
	}
	
	public List<XmlRelatedRevocation> getRelatedRevocations() {
		return signature.getFoundRevocations().getRelatedRevocations();
	}
	
	public List<XmlOrphanRevocation> getOrphanRevocations() {
		return signature.getFoundRevocations().getOrphanRevocations();
	}
	
	public List<XmlRevocationRef> getAllFoundRevocationRefs() {
		List<XmlRevocationRef> revocationRefs = getAllRelatedRevocationRefs();
		revocationRefs.addAll(getAllOrphanRevocationRefs());
		return revocationRefs;
	}
	
	public List<XmlRevocationRef> getAllRelatedRevocationRefs() {
		return getRevocationRefsFromListOfRevocations(getRelatedRevocations());
	}
	
	public List<XmlRevocationRef> getAllOrphanRevocationRefs() {
		return getRevocationRefsFromListOfRevocations(getOrphanRevocations());
	}
	
	private <T extends XmlFoundRevocation> List<XmlRevocationRef> getRevocationRefsFromListOfRevocations(Collection<T> foundRevocations) {
		List<XmlRevocationRef> revocationRefs = new ArrayList<XmlRevocationRef>();
		if (foundRevocations != null) {
			for (T revocation : foundRevocations) {
				revocationRefs.addAll(revocation.getRevocationRefs());
			}
		}
		return revocationRefs;
	}
	
	/**
	 * Returns a list of all found {@link XmlRevocationRef}s with the given {@code origin}
	 * @param origin {@link RevocationRefOrigin} to get values with
	 * @return list of {@link XmlRevocationRef}s
	 */
	public List<XmlRevocationRef> getFoundRevocationRefsByOrigin(RevocationRefOrigin origin) {
		List<XmlRevocationRef> revocationRefs = new ArrayList<XmlRevocationRef>();
		for (XmlRevocationRef ref : getAllFoundRevocationRefs()) {
			if (ref.getOrigins().contains(origin)) {
				revocationRefs.add(ref);
			}
		}
		return revocationRefs;
	}
	
	/**
	 * Returns a list of all {@link XmlRelatedRevocation}s used for the signature validation process
	 * with the given {@code originType}
	 * @param originType {@link RevocationOrigin} to get values with
	 * @return list of {@link XmlRelatedRevocation}s
	 */
	public Set<XmlRelatedRevocation> getRelatedRevocationsByOrigin(RevocationOrigin originType) {
		return filterRevocationsByOrigin(getRelatedRevocations(), originType);
	}

	/**
	 * Returns a list of all {@link XmlOrphanRevocation}s found in the signature, but not used
	 * during the validation process with the given {@code originType}
	 * @param originType {@link RevocationOrigin} to get values with
	 * @return list of {@link XmlOrphanRevocation}s
	 */
	public Set<XmlOrphanRevocation> getOrphanRevocationsByOrigin(RevocationOrigin originType) {
		return filterRevocationsByOrigin(getOrphanRevocations(), originType);
	}
	
	private <T extends XmlFoundRevocation> Set<T> filterRevocationsByOrigin(List<T> revocations, RevocationOrigin originType) {
		Set<T> revocationsWithOrigin = new HashSet<T>();
		if (revocations != null) {
			for (T relatedRevocation : revocations) {
				if (relatedRevocation.getOrigins().contains(originType)) {
					revocationsWithOrigin.add(relatedRevocation);
				}
			}
		}
		return revocationsWithOrigin;
	}
	
	/**
	 * Returns a list of all {@link XmlRelatedRevocation}s used for the signature validation process
	 * with the given {@code type}
	 * @param type {@link RevocationType} to get values with
	 * @return list of {@link XmlRelatedRevocation}s
	 */
	public Set<XmlRelatedRevocation> getRelatedRevocationsByType(RevocationType type) {
		return filterRevocationsByType(getRelatedRevocations(), type);
	}


	/**
	 * Returns a list of all {@link XmlOrphanRevocation}s found in the signature, but not used
	 * during the validation process with the given {@code type}
	 * @param type {@link RevocationType} to get values with
	 * @return list of {@link XmlOrphanRevocation}s
	 */
	public Set<XmlOrphanRevocation> getOrphanRevocationsByType(RevocationType type) {
		return filterRevocationsByType(getOrphanRevocations(), type);
	}
	
	/**
	 * Extracts revocations with a given {@code type} from a list of {@code revocations}
	 * @param <T> extends {@link XmlFoundRevocation}
	 * @param revocations list of {@link XmlFoundRevocation}s to get values with a defined type from
	 * @param type {@link RevocationType} to get values with
	 * @return list of {@link XmlFoundRevocation}s
	 */
	public <T extends XmlFoundRevocation> Set<T> filterRevocationsByType(List<T> revocations, RevocationType type) {
		Set<T> revocationWithType = new HashSet<T>();
		if (revocations != null) {
			for (T revocation : revocations) {
				if (revocation.getType().equals(type)) {
					revocationWithType.add(revocation);
				}
			}
		}
		return revocationWithType;
	}
	
	/**
	 * Returns a list of revocation ids found in the signature
	 * @return list of ids
	 */
	public List<String> getRevocationIds() {
		List<String> revocationIds = new ArrayList<String>();
		List<XmlFoundRevocation> foundRevocations = getAllFoundRevocations();
		for (XmlFoundRevocation foundRevocation : foundRevocations) {
			if (foundRevocation instanceof XmlRelatedRevocation) {
				revocationIds.add(((XmlRelatedRevocation)foundRevocation).getRevocation().getId());
			} else {
				revocationIds.add(((XmlOrphanRevocation)foundRevocation).getToken().getId());
			}
		}
		return revocationIds;
	}

	/**
	 * Returns a list of revocation ids found in the signature with the specified {@code type}
	 * @param type - {@link RevocationType} to find revocations with
	 * @return list of ids
	 */
	public List<String> getRevocationIdsByType(RevocationType type) {
		List<String> revocationIds = new ArrayList<String>();
		for (XmlRelatedRevocation revocationRef : getRelatedRevocationsByType(type)) {
			revocationIds.add(revocationRef.getRevocation().getId());
		}
		for (XmlOrphanRevocation revocationRef : getOrphanRevocationsByType(type)) {
			revocationIds.add(revocationRef.getToken().getId());
		}
		return revocationIds;
	}

	/**
	 * Returns a list of revocation ids found in the signature with the specified {@code origin}
	 * @param origin - {@link RevocationOrigin} to find revocations with
	 * @return list of ids
	 */
	public List<String> getRevocationIdsByOrigin(RevocationOrigin origin) {
		List<String> revocationIds = new ArrayList<String>();
		for (XmlRelatedRevocation revocationRef : getRelatedRevocationsByOrigin(origin)) {
			revocationIds.add(revocationRef.getRevocation().getId());
		}
		for (XmlOrphanRevocation revocationRef : getOrphanRevocationsByOrigin(origin)) {
			revocationIds.add(revocationRef.getToken().getId());
		}
		return revocationIds;
	}
	
	/**
	 * Returns a list of revocation ids found in the signature with the specified {@code type} and {@code origin}
	 * @param type - {@link RevocationType} to find revocations with
	 * @param origin - {@link RevocationOrigin} to find revocations with
	 * @return list of ids
	 */
	public List<String> getRevocationIdsByTypeAndOrigin(RevocationType type, RevocationOrigin origin) {
		List<String> revocationIds = getRevocationIdsByType(type);
		revocationIds.retainAll(getRevocationIdsByOrigin(origin));
		return revocationIds;
	}

	/**
	 * Returns a list of found certificate ids based on the requested {@code origin}
	 * @param origin {@link CertificateOrigin} to get certificate ids for
	 * @return list of certificate ids
	 */
	public List<String> getFoundCertificateIds(CertificateOrigin origin) {
		List<String> result = new ArrayList<String>();
		XmlFoundCertificates foundCertificates = signature.getFoundCertificates();
		if (foundCertificates != null) {
			for (XmlRelatedCertificate xmlRelatedCertificate : foundCertificates.getRelatedCertificates()) {
				if (xmlRelatedCertificate.getOrigins().contains(origin)) {
					result.add(xmlRelatedCertificate.getCertificate().getId());
				}
			}
			for (XmlOrphanCertificate xmlOrphanCertificate : foundCertificates.getOrphanCertificates()) {
				if (xmlOrphanCertificate.getOrigins().contains(origin)) {
					result.add(xmlOrphanCertificate.getToken().getId());
				}
			}
		}
		return result;
	}
	
	/**
	 * Returns a list of found {@link XmlRelatedCertificate}s with the given {@code origin}
	 * @param origin {@link CertificateOrigin} to get certificates with
	 * @return list of {@link XmlRelatedCertificate}
	 */
	public List<XmlRelatedCertificate> getRelatedCertificatesByOrigin(CertificateOrigin origin) {
		List<XmlRelatedCertificate> certificatesByOrigin = new ArrayList<XmlRelatedCertificate>();
		XmlFoundCertificates foundCertificates = signature.getFoundCertificates();
		if (foundCertificates != null) {
			for (XmlRelatedCertificate foundCertificate : foundCertificates.getRelatedCertificates()) {
				if (foundCertificate.getOrigins().contains(origin)) {
					certificatesByOrigin.add(foundCertificate);
				}
			}
		}
		return certificatesByOrigin;
	}
	
	/**
	 * Returns a list of found {@link XmlFoundCertificate} containing a reference
	 * from the given {@code origin}
	 * 
	 * @param origin
	 *               {@link CertificateRefOrigin} of a certificate reference
	 * @return list of found {@link XmlFoundCertificate}
	 */
	public List<XmlFoundCertificate> getFoundCertificatesByRefOrigin(CertificateRefOrigin origin) {
		List<XmlFoundCertificate> certificatesByLocation = new ArrayList<XmlFoundCertificate>();
		for (XmlFoundCertificate foundCertificate : getAllFoundCertificates()) {
			for (XmlCertificateRef certificateRef : foundCertificate.getCertificateRefs()) {
				if (origin.equals(certificateRef.getOrigin())) {
					certificatesByLocation.add(foundCertificate);
				}
			}
		}
		return certificatesByLocation;
	}

	@Override
	public byte[] getBinaries() {
		return signature.getSignatureValue();
	}

}

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
package eu.europa.esig.dss.validation.reports.wrapper;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EndorsementType;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.TimestampLocation;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundCertificates;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundTimestamp;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOrphanCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOrphanRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRelatedCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRelatedRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureDigestReference;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignerDocumentRepresentations;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignerRole;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlStructuralValidation;
import eu.europa.esig.dss.utils.Utils;

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
		return Utils.EMPTY_STRING;
	}

	public Date getDateTime() {
		return signature.getDateTime();
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
		return Utils.isTrue(signature.isCounterSignature());
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

	public Set<TimestampWrapper> getAllTimestampsNotArchival() {
		Set<TimestampWrapper> notArchivalTimestamps = new HashSet<TimestampWrapper>();
		notArchivalTimestamps.addAll(getTimestampListByType(TimestampType.SIGNATURE_TIMESTAMP));
		notArchivalTimestamps.addAll(getTimestampListByType(TimestampType.CONTENT_TIMESTAMP));
		notArchivalTimestamps.addAll(getTimestampListByType(TimestampType.ALL_DATA_OBJECTS_TIMESTAMP));
		notArchivalTimestamps.addAll(getTimestampListByType(TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP));
		return notArchivalTimestamps;
	}

	public boolean isSignatureProductionPlacePresent() {
		return signature.getSignatureProductionPlace() != null;
	}

	public String getAddress() {
		return signature.getSignatureProductionPlace().getAddress();
	}

	public String getCity() {
		return signature.getSignatureProductionPlace().getCity();
	}

	public String getCountryName() {
		return signature.getSignatureProductionPlace().getCountryName();
	}

	public String getPostalCode() {
		return signature.getSignatureProductionPlace().getPostalCode();
	}

	public String getStateOrProvince() {
		return signature.getSignatureProductionPlace().getStateOrProvince();
	}

	public String getSignatureFormat() {
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
		return Utils.EMPTY_STRING;
	}

	public boolean isBLevelTechnicallyValid() {
		return (signature.getBasicSignature() != null) && signature.getBasicSignature().isSignatureValid();
	}

	public boolean isThereXLevel() {
		List<TimestampWrapper> timestampLevelX = getTimestampLevelX();
		return Utils.isCollectionNotEmpty(timestampLevelX);
	}

	public boolean isXLevelTechnicallyValid() {
		List<TimestampWrapper> timestamps = getTimestampLevelX();
		return isTimestampValid(timestamps);
	}

	private List<TimestampWrapper> getTimestampLevelX() {
		List<TimestampWrapper> timestamps = getTimestampListByType(TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
		timestamps.addAll(getTimestampListByType(TimestampType.VALIDATION_DATA_TIMESTAMP));
		return timestamps;
	}

	public boolean isThereALevel() {
		List<TimestampWrapper> timestampList = getArchiveTimestamps();
		return Utils.isCollectionNotEmpty(timestampList);
	}

	public boolean isALevelTechnicallyValid() {
		List<TimestampWrapper> timestampList = getArchiveTimestamps();
		return isTimestampValid(timestampList);
	}

	private List<TimestampWrapper> getArchiveTimestamps() {
		return getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP);
	}

	public boolean isThereTLevel() {
		List<TimestampWrapper> timestamps = getSignatureTimestamps();
		return Utils.isCollectionNotEmpty(timestamps);
	}

	public boolean isTLevelTechnicallyValid() {
		List<TimestampWrapper> timestampList = getSignatureTimestamps();
		return isTimestampValid(timestampList);
	}

	private List<TimestampWrapper> getSignatureTimestamps() {
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
		if (Utils.isCollectionNotEmpty(timestamps)) {
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
		if (Utils.isCollectionNotEmpty(commitmentTypeIndications)) {
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
		return Utils.EMPTY_STRING;
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
		if (policy != null && Utils.isStringNotEmpty(policy.getDescription())) {
			return policy.getDescription();
		}
		return Utils.EMPTY_STRING;
	}

	public String getPolicyNotice() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getNotice();
		}
		return Utils.EMPTY_STRING;
	}

	public String getPolicyUrl() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return policy.getUrl();
		}
		return Utils.EMPTY_STRING;
	}

	public boolean isPolicyAsn1Processable() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return Utils.isTrue(policy.isAsn1Processable());
		}
		return false;
	}

	public boolean isPolicyIdentified() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return Utils.isTrue(policy.isIdentified());
		}
		return false;
	}

	public boolean isPolicyStatus() {
		XmlPolicy policy = signature.getPolicy();
		if (policy != null) {
			return Utils.isTrue(policy.isStatus());
		}
		return false;
	}

	public String getFormat() {
		return signature.getSignatureFormat();
	}
	
	public String getSignatureFieldName() {
		XmlPDFSignatureDictionary pdfSignatureDictionary = signature.getPDFSignatureDictionary();
		if (pdfSignatureDictionary != null) {
			return pdfSignatureDictionary.getSignatureFieldName();
		}
		return null;
	}

	public String getSignerName() {
		XmlPDFSignatureDictionary pdfSignatureDictionary = signature.getPDFSignatureDictionary();
		if (pdfSignatureDictionary != null) {
			return pdfSignatureDictionary.getSignerName();
		}
		return null;
	}

	public String getFilter() {
		XmlPDFSignatureDictionary pdfSignatureDictionary = signature.getPDFSignatureDictionary();
		if (pdfSignatureDictionary != null) {
			return pdfSignatureDictionary.getFilter();
		}
		return null;
	}

	public String getSubFilter() {
		XmlPDFSignatureDictionary pdfSignatureDictionary = signature.getPDFSignatureDictionary();
		if (pdfSignatureDictionary != null) {
			return pdfSignatureDictionary.getSubFilter();
		}
		return null;
	}

	public String getContactInfo() {
		XmlPDFSignatureDictionary pdfSignatureDictionary = signature.getPDFSignatureDictionary();
		if (pdfSignatureDictionary != null) {
			return pdfSignatureDictionary.getContactInfo();
		}
		return null;
	}

	public String getReason() {
		XmlPDFSignatureDictionary pdfSignatureDictionary = signature.getPDFSignatureDictionary();
		if (pdfSignatureDictionary != null) {
			return pdfSignatureDictionary.getReason();
		}
		return null;
	}
	
	public List<BigInteger> getSignatureByteRange() {
		XmlPDFSignatureDictionary pdfSignatureDictionary = signature.getPDFSignatureDictionary();
		if (pdfSignatureDictionary != null) {
			return pdfSignatureDictionary.getSignatureByteRange();
		}
		return null;
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

}

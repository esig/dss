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
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateLocationType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertifiedRole;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestMatcher;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundRevocations;
import eu.europa.esig.dss.jaxb.diagnostic.XmlFoundTimestamp;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPDFSignatureDictionary;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRelatedRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationRef;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignatureScope;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlStructuralValidation;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.DigestMatcherType;
import eu.europa.esig.dss.validation.RevocationRefLocation;
import eu.europa.esig.dss.validation.RevocationType;
import eu.europa.esig.dss.validation.XmlRevocationOrigin;
import eu.europa.esig.dss.x509.TimestampType;

public class SignatureWrapper extends AbstractTokenProxy {

	private final XmlSignature signature;

	public SignatureWrapper(XmlSignature signature) {
		this.signature = signature;
	}

	@Override
	public String getId() {
		return signature.getId();
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
			if (timestampType.name().equals(tsp.getType())) {
				result.add(tsp);
			}
		}
		return result;
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

	public List<String> getCertifiedRoles() {
		List<String> result = new ArrayList<String>();
		List<XmlCertifiedRole> certifiedRoles = signature.getCertifiedRoles();
		if (Utils.isCollectionNotEmpty(certifiedRoles)) {
			for (XmlCertifiedRole certifiedRole : certifiedRoles) {
				result.add(certifiedRole.getCertifiedRole());
			}
		}
		return result;
	}

	public List<String> getCommitmentTypeIdentifiers() {
		List<String> commitmentTypeIndications = signature.getCommitmentTypeIndication();
		if (Utils.isCollectionNotEmpty(commitmentTypeIndications)) {
			return commitmentTypeIndications;
		}
		return Collections.emptyList();
	}

	public List<String> getClaimedRoles() {
		List<String> claimedRoles = signature.getClaimedRoles();
		if (Utils.isCollectionNotEmpty(claimedRoles)) {
			return claimedRoles;
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

	public String getSignatureName() {
		XmlPDFSignatureDictionary pdfSignatureDictionary = signature.getPDFSignatureDictionary();
		if (pdfSignatureDictionary != null) {
			return pdfSignatureDictionary.getSignatureName();
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
	
	public XmlFoundRevocations getFoundRevocations() {
		return signature.getFoundRevocations();
	}
	
	public List<XmlRevocationRef> getAllFoundRevocationRefs() {
		List<XmlRevocationRef> revocationRefs = new ArrayList<XmlRevocationRef>();
		List<String> storedXmlRevocationIds = new ArrayList<String>(); // we do not need to collect references for the same revocations twice
		XmlFoundRevocations foundRevocations = getFoundRevocations();
		for (XmlRelatedRevocation revocation : foundRevocations.getRelatedRevocation()) {
			if (!storedXmlRevocationIds.contains(revocation.getRevocation().getId())) {
				storedXmlRevocationIds.add(revocation.getRevocation().getId());
				revocationRefs.addAll(revocation.getRevocationReferences());
			}
		}
		revocationRefs.addAll(foundRevocations.getUnusedRevocationRefs());
		return revocationRefs;
	}
	
	public List<XmlRevocationRef> getFoundRevocationRefsByLocation(RevocationRefLocation revocationRefLocation) {
		List<XmlRevocationRef> revocationRefs = new ArrayList<XmlRevocationRef>();
		for (XmlRevocationRef ref : getAllFoundRevocationRefs()) {
			if (ref.getLocation().equals(revocationRefLocation)) {
				revocationRefs.add(ref);
			}
		}
		return revocationRefs;
	}
	
	public Set<XmlRelatedRevocation> getRelatedRevocationsByOrigin(XmlRevocationOrigin originType) {
		Set<XmlRelatedRevocation> revocationWithOrigin = new HashSet<XmlRelatedRevocation>();
		for (XmlRelatedRevocation revocationRef : getFoundRevocations().getRelatedRevocation()) {
			if (revocationRef.getOrigin().equals(originType)) {
				revocationWithOrigin.add(revocationRef);
			}
		}
		return revocationWithOrigin;
	}
	
	public Set<XmlRelatedRevocation> getRelatedRevocationsByType(RevocationType type) {
		Set<XmlRelatedRevocation> revocationWithType = new HashSet<XmlRelatedRevocation>();
		for (XmlRelatedRevocation revocationRef : getFoundRevocations().getRelatedRevocation()) {
			if (revocationRef.getType().equals(type)) {
				revocationWithType.add(revocationRef);
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
		for (XmlRelatedRevocation revocationRef : getFoundRevocations().getRelatedRevocation()) {
			revocationIds.add(revocationRef.getRevocation().getId());
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
		return revocationIds;
	}

	/**
	 * Returns a list of revocation ids found in the signature with the specified {@code origin}
	 * @param origin - {@link XmlRevocationOrigin} to find revocations with
	 * @return list of ids
	 */
	public List<String> getRevocationIdsByOrigin(XmlRevocationOrigin origin) {
		List<String> revocationIds = new ArrayList<String>();
		for (XmlRelatedRevocation revocationRef : getRelatedRevocationsByOrigin(origin)) {
			revocationIds.add(revocationRef.getRevocation().getId());
		}
		return revocationIds;
	}
	
	/**
	 * Returns a list of revocation ids found in the signature with the specified {@code type} and {@code origin}
	 * @param type - {@link RevocationType} to find revocations with
	 * @param origin - {@link XmlRevocationOrigin} to find revocations with
	 * @return list of ids
	 */
	public List<String> getRevocationIdsByTypeAndOrigin(RevocationType type, XmlRevocationOrigin origin) {
		List<String> revocationIds = getRevocationIdsByType(type);
		revocationIds.retainAll(getRevocationIdsByOrigin(origin));
		return revocationIds;
	}

	public List<String> getFoundCertificateIds(XmlCertificateLocationType locationType) {
		List<String> result = new ArrayList<String>();
		List<XmlFoundCertificate> foundCertificates = signature.getFoundCertificates();
		if (Utils.isCollectionNotEmpty(foundCertificates)) {
			for (XmlFoundCertificate xmlFoundCertificate : foundCertificates) {
				if (locationType.equals(xmlFoundCertificate.getLocation())) {
					result.add(xmlFoundCertificate.getCertificate().getId());
				}
			}
		}
		return result;
	}

}

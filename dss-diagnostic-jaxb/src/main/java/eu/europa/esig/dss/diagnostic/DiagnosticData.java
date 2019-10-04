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

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOrphanToken;
import eu.europa.esig.dss.diagnostic.jaxb.XmlRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignerData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestamp;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedList;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.MaskGenerationFunction;
import eu.europa.esig.dss.enumerations.OrphanTokenType;
import eu.europa.esig.dss.enumerations.RevocationReason;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;

/**
 * This class represents all static data extracted by the process analysing the signature. They are independent from the
 * validation policy to be applied.
 */
public class DiagnosticData {

	private final XmlDiagnosticData wrapped;

	private List<SignatureWrapper> foundSignatures;
	private List<CertificateWrapper> usedCertificates;
	private List<TimestampWrapper> usedTimestamps;

	public DiagnosticData(final XmlDiagnosticData wrapped) {
		this.wrapped = wrapped;
	}

	public String getDocumentName() {
		return wrapped.getDocumentName();
	}

	/**
	 * This method returns the list of the signature id. The result is stored in the local variable.
	 *
	 * @return list of signature ids, is never null, can be empty
	 */
	public List<String> getSignatureIdList() {
		List<String> signatureIds = new ArrayList<String>();
		List<XmlSignature> signatures = wrapped.getSignatures();
		if (signatures != null) {
			for (XmlSignature xmlSignature : signatures) {
				signatureIds.add(xmlSignature.getId());
			}
		}
		return signatureIds;
	}

	/**
	 * This method returns the first signature id.
	 *
	 * @return the first signature id
	 */
	public String getFirstSignatureId() {
		SignatureWrapper firstSignature = getFirstSignatureNullSafe();
		return firstSignature.getId();
	}

	/**
	 * This method returns the first signature time.
	 *
	 * @return the first signature time
	 */
	public Date getFirstSignatureDate() {
		SignatureWrapper firstSignature = getFirstSignatureNullSafe();
		return firstSignature.getDateTime();
	}

	/**
	 * This method returns the claimed signing time.
	 *
	 * @param signatureId
	 *            The identifier of the signature, for which the date is sought.
	 * @return the signature time for the given signature
	 */
	public Date getSignatureDate(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.getDateTime();
	}

	/**
	 * This method returns the signature format for the first signature.
	 *
	 * @return The first signature format
	 */
	public SignatureLevel getFirstSignatureFormat() {
		SignatureWrapper signature = getFirstSignatureNullSafe();
		return signature.getSignatureFormat();
	}

	/**
	 * This method returns the signature format for the given signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature, for which the format is sought.
	 * @return The signature format
	 */
	public SignatureLevel getSignatureFormat(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.getSignatureFormat();
	}

	/**
	 * This method returns the {@code DigestAlgorithm} of the first signature.
	 *
	 * @return The {@code DigestAlgorithm} of the first signature
	 */
	public DigestAlgorithm getFirstSignatureDigestAlgorithm() {
		SignatureWrapper signature = getFirstSignatureNullSafe();
		return signature.getDigestAlgorithm();
	}

	/**
	 * This method returns the {@code DigestAlgorithm} for the given signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature, for which the algorithm is sought.
	 * @return The {@code DigestAlgorithm} for the given signature
	 */
	public DigestAlgorithm getSignatureDigestAlgorithm(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.getDigestAlgorithm();
	}

	/**
	 * This method returns the {@code EncryptionAlgorithm} of the first signature.
	 *
	 * @return The {@code EncryptionAlgorithm} of the first signature
	 */
	public EncryptionAlgorithm getFirstSignatureEncryptionAlgorithm() {
		SignatureWrapper signature = getFirstSignatureNullSafe();
		return signature.getEncryptionAlgorithm();
	}

	/**
	 * This method returns the {@code DigestAlgorithm} for the given signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature, for which the algorithm is sought.
	 * @return The {@code DigestAlgorithm} for the given signature
	 */
	public EncryptionAlgorithm getSignatureEncryptionAlgorithm(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.getEncryptionAlgorithm();
	}

	/**
	 * This method returns the {@code MaskGenerationFunction} for the given signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature, for which the algorithm is sought.
	 * @return The {@code MaskGenerationFunction} for the given signature
	 */
	public MaskGenerationFunction getSignatureMaskGenerationFunction(String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.getMaskGenerationFunction();
	}

	/**
	 * This method returns signing certificate dss id for the first signature.
	 *
	 * @return signing certificate dss id.
	 */
	public String getFirstSigningCertificateId() {
		SignatureWrapper signature = getFirstSignatureNullSafe();
		return signature.getSigningCertificate().getId();
	}

	/**
	 * This method returns signing certificate dss id for the given signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature, for which the signing certificate is sought.
	 * @return signing certificate dss id for the given signature.
	 */
	public String getSigningCertificateId(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.getSigningCertificate().getId();
	}

	/**
	 * This method indicates if the digest value and the issuer and serial match for the signing certificate .
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the digest value and the issuer and serial match.
	 */
	public boolean isSigningCertificateIdentified(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.isSigningCertificateIdentified();
	}

	/**
	 * This method returns the list of certificates in the chain of the main signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return list of certificate's dss id for the given signature.
	 */
	public List<String> getSignatureCertificateChain(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		List<String> result = new ArrayList<String>();
		for (CertificateWrapper certWrapper : signature.getCertificateChain()) {
			result.add(certWrapper.getId());
		}
		return result;
	}

	/**
	 * The identifier of the policy of the first signature.
	 *
	 * @return the policy identifier of the first signature
	 */
	public String getFirstPolicyId() {
		SignatureWrapper signature = getFirstSignatureNullSafe();
		return signature.getPolicyId();
	}

	/**
	 * The identifier of the policy.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return the policy identifier
	 */
	public String getPolicyId(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.getPolicyId();
	}


	/**
	 * The description of the policy.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return the policy description
	 */
	public String getPolicyDescription(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.getPolicyDescription();
	}

	/**
	 * This method returns the list of identifier of the timestamps related to the given signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return The list of identifier of the timestamps
	 */
	public List<String> getTimestampIdList(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.getTimestampIdsList();
	}

	/**
	 * This method returns the list of timestamps wrappers which covers the given signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return The list of timestamp wrappers
	 */
	public List<TimestampWrapper> getTimestampList(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.getTimestampList();
	}

	/**
	 * Indicates if the -B level is technically valid. It means that the signature value is valid.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the signature value is valid
	 */
	public boolean isBLevelTechnicallyValid(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.isBLevelTechnicallyValid();
	}

	/**
	 * Indicates if there is a signature timestamp.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the signature timestamp is present
	 */
	public boolean isThereTLevel(final String signatureId) {
		SignatureWrapper signatureWrapper = getSignatureByIdNullSafe(signatureId);
		return signatureWrapper.isThereTLevel();
	}

	/**
	 * Indicates if the -T level is technically valid. It means that the signature and the digest are valid.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the signature and digest are valid
	 */
	public boolean isTLevelTechnicallyValid(final String signatureId) {
		SignatureWrapper signatureWrapper = getSignatureByIdNullSafe(signatureId);
		return signatureWrapper.isTLevelTechnicallyValid();
	}

	/**
	 * Indicates if there is an -X1 or -X2 timestamp.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the -X1 or -X2 is present
	 */
	public boolean isThereXLevel(final String signatureId) {
		SignatureWrapper signatureWrapper = getSignatureByIdNullSafe(signatureId);
		return signatureWrapper.isThereXLevel();
	}

	/**
	 * Indicates if the -X level is technically valid. It means that the signature and the digest are valid.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the signature and digest are valid
	 */
	public boolean isXLevelTechnicallyValid(final String signatureId) {
		SignatureWrapper signatureWrapper = getSignatureByIdNullSafe(signatureId);
		return signatureWrapper.isXLevelTechnicallyValid();
	}

	/**
	 * Indicates if there is an archive timestamp.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the archive timestamp is present
	 */
	public boolean isThereALevel(final String signatureId) {
		SignatureWrapper signatureWrapper = getSignatureByIdNullSafe(signatureId);
		return signatureWrapper.isThereALevel();
	}

	/**
	 * Indicates if the -A (-LTA) level is technically valid. It means that the signature of the archive timestamps are
	 * valid and their imprint is valid too.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the signature and digest are valid
	 */
	public boolean isALevelTechnicallyValid(final String signatureId) {
		SignatureWrapper signatureWrapper = getSignatureByIdNullSafe(signatureId);
		return signatureWrapper.isALevelTechnicallyValid();
	}

	/**
	 * Returns the identifier of the timestamp signing certificate.
	 *
	 * @param timestampId
	 *            timestamp id
	 * @return signing certificate id
	 */
	public String getTimestampSigningCertificateId(final String timestampId) {
		TimestampWrapper timestamp = getTimestampByIdNullSafe(timestampId);
		return timestamp.getSigningCertificate().getId();
	}

	/**
	 * This method returns the timestamp type of the given timestamp
	 * 
	 * @param timestampId
	 *            the timestamp id
	 * @return the related timestamp type
	 */
	public TimestampType getTimestampType(String timestampId) {
		TimestampWrapper timestamp = getTimestampByIdNullSafe(timestampId);
		return timestamp.getType();
	}

	/**
	 * This method indicates if the certificate signature is valid and the revocation status is valid.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return certificate validity
	 */
	public boolean isValidCertificate(final String dssCertificateId) {
		CertificateWrapper certificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		
		final boolean signatureValid = (certificate.getCurrentBasicSignature() != null) && certificate.getCurrentBasicSignature().isSignatureValid();
		CertificateRevocationWrapper latestRevocationData = getLatestRevocationDataForCertificate(certificate) ;
		final boolean revocationValid = (latestRevocationData != null) && latestRevocationData.isStatus();
		final boolean trusted = certificate.isTrusted();

		final boolean validity = signatureValid && (trusted ? true : revocationValid);
		return validity;
	}

	/**
	 * This method returns the subject distinguished name for the given dss certificate identifier.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return subject distinguished name
	 */
	public String getCertificateDN(final String dssCertificateId) {
		CertificateWrapper certificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		return certificate.getCertificateDN();
	}

	/**
	 * This method returns the issuer distinguished name for the given dss certificate identifier.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return issuer distinguished name
	 */
	public String getCertificateIssuerDN(final String dssCertificateId) {
		CertificateWrapper certificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		return certificate.getCertificateIssuerDN();
	}

	/**
	 * This method returns the serial number of the given dss certificate identifier.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return serial number
	 */
	public String getCertificateSerialNumber(final String dssCertificateId) {
		CertificateWrapper certificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		return certificate.getSerialNumber();
	}

	/**
	 * This method returns the revocation source for the given certificate.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return revocation source
	 */
	public RevocationType getCertificateRevocationSource(final String dssCertificateId) {
		CertificateWrapper certificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		if (certificate.isRevocationDataAvailable()) {
			return getLatestRevocationDataForCertificate(certificate).getRevocationType();
		}
		return null;
	}

	/**
	 * This method returns the revocation status for the given certificate.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return revocation status
	 */
	public boolean getCertificateRevocationStatus(final String dssCertificateId) {
		CertificateWrapper certificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		if (certificate.isRevocationDataAvailable()) {
			return getLatestRevocationDataForCertificate(certificate).isStatus();
		}
		return false;
	}

	/**
	 * This method returns the revocation reason for the given certificate.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return revocation reason
	 */
	public RevocationReason getCertificateRevocationReason(String dssCertificateId) {
		CertificateWrapper certificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		if (certificate.isRevocationDataAvailable()) {
			return getLatestRevocationDataForCertificate(certificate).getReason();
		}
		return null;
	}

	/**
	 * This method retrieves the error message for the given signature id
	 * 
	 * @param signatureId
	 *            the signature id
	 * @return the error message
	 */
	public String getErrorMessage(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.getErrorMessage();
	}

	private SignatureWrapper getFirstSignatureNullSafe() {
		List<SignatureWrapper> signatures = getSignatures();
		if (signatures != null && signatures.size() > 0) {
			return signatures.get(0);
		}
		return new SignatureWrapper(new XmlSignature()); // TODO improve ?
	}

	/**
	 * This method returns a signature wrapper for the given signature id
	 * 
	 * @param id
	 *            the signature id
	 * @return a signature wrapper or null
	 */
	public SignatureWrapper getSignatureById(String id) {
		List<SignatureWrapper> signatures = getSignatures();
		if (signatures != null) {
			for (SignatureWrapper xmlSignature : signatures) {
				if (id.equals(xmlSignature.getId())) {
					return xmlSignature;
				}
			}
		}
		return null;
	}

	private SignatureWrapper getSignatureByIdNullSafe(String id) {
		List<SignatureWrapper> signatures = getSignatures();
		if (signatures != null) {
			for (SignatureWrapper xmlSignature : signatures) {
				if (id.equals(xmlSignature.getId())) {
					return xmlSignature;
				}
			}
		}
		return new SignatureWrapper(new XmlSignature()); // TODO improve ?
	}

	private TimestampWrapper getTimestampByIdNullSafe(String id) {
		TimestampWrapper timestamp = getTimestampById(id);
		if (timestamp != null) {
			return timestamp;
		}
		return new TimestampWrapper(new XmlTimestamp());
	}
	
	/**
	 * Returns the TimestampWrapper corresponding to the given id.
	 *
	 * @param id
	 *            timestamp id
	 * @return timestamp wrapper or null
	 */
	public TimestampWrapper getTimestampById(String id) {
		Set<TimestampWrapper> allTimestamps = getTimestampSet();
		for (TimestampWrapper timestampWrapper : allTimestamps) {
			if (id.equals(timestampWrapper.getId())) {
				return timestampWrapper;
			}
		}
		return null;
	}

	/**
	 * This method returns a certificate wrapper for the given certificate id
	 * 
	 * @param id
	 *           the certificate id
	 * @return a certificate wrapper (or empty object)
	 */
	public CertificateWrapper getUsedCertificateByIdNullSafe(String id) {
		CertificateWrapper cert = getUsedCertificateById(id);
		if (cert != null) {
			return cert;
		}
		return new CertificateWrapper(new XmlCertificate()); // TODO improve ?
	}

	/**
	 * This method returns a certificate wrapper for the given certificate id
	 * 
	 * @param id
	 *            the certificate id
	 * @return a certificate wrapper or null
	 */
	public CertificateWrapper getUsedCertificateById(String id) {
		List<CertificateWrapper> certificates = getUsedCertificates();
		if (certificates != null) {
			for (CertificateWrapper certificate : certificates) {
				if (id.equals(certificate.getId())) {
					return certificate;
				}
			}
		}
		return null;
	}
	
	/**
	 * Returns a list of certificates by their origin source
	 * @param certificateSourceType {@link CertificateSourceType} to get certificates with
	 * @return list of {@link CertificateWrapper}s
	 */
	public List<CertificateWrapper> getCertificatesFromSource(CertificateSourceType certificateSourceType) {
		List<CertificateWrapper> certificates = new ArrayList<CertificateWrapper>();
		for (CertificateWrapper certificate : getUsedCertificates()) {
			if (certificate.getSources().contains(certificateSourceType)) {
				certificates.add(certificate);
			}
		}
		return certificates;
	}
	
	/**
	 * Returns a list of all found {@link XmlOrphanRevocation}s
	 * @return list of {@link XmlOrphanRevocation}s
	 */
	public List<XmlOrphanRevocation> getAllOrphanRevocations() {
		List<XmlOrphanRevocation> orphanRevocations = new ArrayList<XmlOrphanRevocation>();
		for (SignatureWrapper signatureWrapper : getSignatures()) {
			orphanRevocations.addAll(signatureWrapper.getOrphanRevocations());
		}
		return orphanRevocations;
	}
	
	/**
	 * Returns a list of all found {@link XmlOrphanToken} certificates
	 * @return list of {@link XmlOrphanToken}s
	 */
	public List<XmlOrphanToken> getAllOrphanCertificates() {
		List<XmlOrphanToken> orphanCertificateTokens = new ArrayList<XmlOrphanToken>();
		for (XmlOrphanToken orphanToken : wrapped.getOrphanTokens()) {
			if (OrphanTokenType.CERTIFICATE.equals(orphanToken.getType())) {
				orphanCertificateTokens.add(orphanToken);
			}
		}
		return orphanCertificateTokens;
	}

	/**
	 * This method retrieves a list of signature wrappers.
	 * 
	 * @return a list of {@link SignatureWrapper}s.
	 */
	public List<SignatureWrapper> getSignatures() {
		if (foundSignatures == null) {
			foundSignatures = new ArrayList<SignatureWrapper>();
			List<XmlSignature> xmlSignatures = wrapped.getSignatures();
			if (xmlSignatures != null) {
				for (XmlSignature xmlSignature : xmlSignatures) {
					foundSignatures.add(new SignatureWrapper(xmlSignature));
				}
			}
		}
		return foundSignatures;
	}

	/**
	 * This method retrieves a set of timestamp wrappers
	 * 
	 * @return a List of timestamp wrappers
	 */
	public List<TimestampWrapper> getTimestampList() {
		if (usedTimestamps == null) {
			usedTimestamps = new ArrayList<TimestampWrapper>();
			List<XmlTimestamp> xmlTimestamps = wrapped.getUsedTimestamps();
			if (xmlTimestamps != null) {
				for (XmlTimestamp xmlTimestamp : xmlTimestamps) {
					usedTimestamps.add(new TimestampWrapper(xmlTimestamp));
				}
			}
		}
		return usedTimestamps;
	}

	/**
	 * This method retrieves a list of certificate wrappers
	 * 
	 * @return a list of {@link CertificateWrapper}s.
	 */
	public List<CertificateWrapper> getUsedCertificates() {
		if (usedCertificates == null) {
			usedCertificates = new ArrayList<CertificateWrapper>();
			List<XmlCertificate> xmlCertificates = wrapped.getUsedCertificates();
			if (xmlCertificates != null) {
				for (XmlCertificate certificate : xmlCertificates) {
					usedCertificates.add(new CertificateWrapper(certificate));
				}
			}
		}
		return usedCertificates;
	}

	/**
	 * This method returns signatures (not countersignatures)
	 * 
	 * @return a set of SignatureWrapper
	 */
	public Set<SignatureWrapper> getAllSignatures() {
		Set<SignatureWrapper> signatures = new HashSet<SignatureWrapper>();
		List<SignatureWrapper> mixedSignatures = getSignatures();
		for (SignatureWrapper signatureWrapper : mixedSignatures) {
			if (signatureWrapper.getParent() == null) {
				signatures.add(signatureWrapper);
			}
		}
		return signatures;
	}

	/**
	 * This method returns counter-signatures (not signatures)
	 * 
	 * @return a set of SignatureWrapper
	 */
	public Set<SignatureWrapper> getAllCounterSignatures() {
		Set<SignatureWrapper> signatures = new HashSet<SignatureWrapper>();
		List<SignatureWrapper> mixedSignatures = getSignatures();
		for (SignatureWrapper signatureWrapper : mixedSignatures) {
			if (signatureWrapper.getParent() != null) {
				signatures.add(signatureWrapper);
			}
		}
		return signatures;
	}
	
	/**
	 * Returns a set of {@link SignatureWrapper}s for a given {@code masterSignatureWrapper}
	 * @param masterSignatureWrapper - {@link SignatureWrapper} to get counter signatures for
	 * @return set of {@link SignatureWrapper}s
	 */
	public Set<SignatureWrapper> getAllCounterSignaturesForMasterSignature(SignatureWrapper masterSignatureWrapper) {
		Set<SignatureWrapper> signatures = new HashSet<SignatureWrapper>();
		List<SignatureWrapper> mixedSignatures = getSignatures();
		for (SignatureWrapper signatureWrapper : mixedSignatures) {
			if (signatureWrapper.getParent() != null && signatureWrapper.getParent().equals(masterSignatureWrapper)) {
				signatures.add(signatureWrapper);
			}
		}
		return signatures;
	}

	/**
	 * This method returns timestamps
	 * 
	 * @return a set of TimestampWrapper
	 */
	public Set<TimestampWrapper> getTimestampSet() {
		return new HashSet<TimestampWrapper>(getTimestampList());
	}

	/**
	 * This method returns all revocation data
	 * 
	 * @return a set of revocation data
	 */
	public Set<RevocationWrapper> getAllRevocationData() {
		Set<RevocationWrapper> revocationData = new HashSet<RevocationWrapper>();
		for (XmlRevocation xmlRevocation : wrapped.getUsedRevocations()) {
			revocationData.add(new RevocationWrapper(xmlRevocation));
		}
		return revocationData;
	}
	
	/**
	 * Returns the last actual revocation for the given {@code certificate}
	 * @param certificate {@link CertificateWrapper} to find the latest revocation for
	 * @return {@link CertificateRevocationWrapper} revocation
	 */
	public CertificateRevocationWrapper getLatestRevocationDataForCertificate(CertificateWrapper certificate) {
		CertificateRevocationWrapper latest = null;
		List<CertificateRevocationWrapper> certificateRevocationData = certificate.getCertificateRevocationData();
		for (CertificateRevocationWrapper certRevoc : certificateRevocationData) {
			if (latest == null || (latest.getProductionDate() != null && certRevoc != null && certRevoc.getProductionDate() != null
					&& certRevoc.getProductionDate().after(latest.getProductionDate()))) {
				latest = certRevoc;
			}
		}
		return latest;
	}
	
	/**
	 * Returns {@link RevocationWrapper} with the given {@code id}
	 * @param id {@link String} identifier to get {@link RevocationWrapper} with
	 * @return {@link RevocationWrapper}
	 */
	public RevocationWrapper getRevocationById(String id) {
		for (RevocationWrapper revocationWrapper : getAllRevocationData()) {
			if (id.equals(revocationWrapper.getId())) {
				return revocationWrapper;
			}
		}
		return null;
	}
	
	/**
	 * Returns a complete list of original signer documents signed by all signatures
	 * @return list of {@link XmlSignerData}s
	 */
	public List<XmlSignerData> getOriginalSignerDocuments() {
		return wrapped.getOriginalDocuments();
	}

	/**
	 * This method returns the JAXB model
	 * 
	 * @return the jaxb model of the diagnostic data
	 */
	public XmlDiagnosticData getJaxbModel() {
		return wrapped;
	}

	/**
	 * This method checks if the document is a container (ASiC)
	 * 
	 * @return true if the document is a container
	 */
	public boolean isContainerInfoPresent() {
		return wrapped.getContainerInfo() != null;
	}

	/**
	 * This method returns the container type
	 * 
	 * @return the container type (ASiC-S/E)
	 */
	public String getContainerType() {
		XmlContainerInfo containerInfo = wrapped.getContainerInfo();
		if (containerInfo != null) {
			return containerInfo.getContainerType();
		}
		return null;
	}

	/**
	 * This method returns the zip comment (if the document is a container)
	 * 
	 * @return the zip comment for the current document (if container) or null
	 */
	public String getZipComment() {
		XmlContainerInfo containerInfo = wrapped.getContainerInfo();
		if (containerInfo != null) {
			return containerInfo.getZipComment();
		}
		return null;
	}

	/**
	 * This method checks if the container has a mimetype file
	 * 
	 * @return true if the mimetype file is present
	 */
	public boolean isMimetypeFilePresent() {
		XmlContainerInfo containerInfo = wrapped.getContainerInfo();
		if (containerInfo != null) {
			return containerInfo.isMimeTypeFilePresent();
		}
		return false;
	}

	/**
	 * This method returns the content of the mimetype file (if container)
	 * 
	 * @return the content of the mimetype file
	 */
	public String getMimetypeFileContent() {
		XmlContainerInfo containerInfo = wrapped.getContainerInfo();
		if (containerInfo != null) {
			return containerInfo.getMimeTypeContent();
		}
		return null;
	}

	public XmlContainerInfo getContainerInfo() {
		return wrapped.getContainerInfo();
	}

	/**
	 * This method returns the JAXB model of the used trusted lists
	 * 
	 * @return the JAXB model of the used trusted lists
	 */
	public List<XmlTrustedList> getTrustedLists() {
		return wrapped.getTrustedLists();
	}

	/**
	 * This method returns the JAXB model of the LOTL
	 * 
	 * @return the JAXB model of the LOTL
	 */
	public List<XmlTrustedList> getListOfTrustedLists() {
		return wrapped.getListOfTrustedLists();
	}

	public Date getValidationDate() {
		return wrapped.getValidationDate();
	}

}

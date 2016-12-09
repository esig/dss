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

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProviderType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlUsedCertificates;
import eu.europa.esig.dss.x509.TimestampType;

/**
 * This class represents all static data extracted by the process analysing the signature. They are independent from the
 * validation policy to be applied.
 */
public class DiagnosticData {

	private final eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData diagnosticData;

	private List<SignatureWrapper> foundSignatures;
	private List<CertificateWrapper> usedCertificates;

	public DiagnosticData(final eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData diagnosticData) {
		this.diagnosticData = diagnosticData;
	}

	public String getDocumentName() {
		return diagnosticData.getDocumentName();
	}

	/**
	 * This method returns the list of the signature id. The result is stored in the local variable.
	 *
	 * @return list of signature ids, is never null, can be empty
	 */
	public List<String> getSignatureIdList() {
		List<String> signatureIds = new ArrayList<String>();
		List<XmlSignature> signatures = diagnosticData.getSignature();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (XmlSignature xmlSignature : signatures) {
				signatureIds.add(xmlSignature.getId());
			}
		}
		return signatureIds;
	}

	/**
	 * This method returns the first signature id.
	 *
	 * @return
	 */
	public String getFirstSignatureId() {
		SignatureWrapper firstSignature = getFirstSignatureNullSafe();
		return firstSignature.getId();
	}

	public Date getSignatureDate() {
		SignatureWrapper firstSignature = getFirstSignatureNullSafe();
		return firstSignature.getDateTime();
	}

	/**
	 * This method returns the claimed signing time.
	 *
	 * @param signatureId
	 *            The identifier of the signature, for which the date is sought.
	 * @return
	 */
	public Date getSignatureDate(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.getDateTime();
	}

	/**
	 * This method returns the signature format for the first signature.
	 *
	 * @return The signature format
	 */
	public String getSignatureFormat() {
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
	public String getSignatureFormat(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.getSignatureFormat();
	}

	/**
	 * This method returns the {@code DigestAlgorithm} of the first signature.
	 *
	 * @return The {@code DigestAlgorithm} of the first signature
	 */
	public DigestAlgorithm getSignatureDigestAlgorithm() {
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
	public EncryptionAlgorithm getSignatureEncryptionAlgorithm() {
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
	 * This method returns signing certificate dss id for the first signature.
	 *
	 * @return signing certificate dss id.
	 */
	public String getSigningCertificateId() {
		SignatureWrapper signature = getFirstSignatureNullSafe();
		return signature.getSigningCertificateId();
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
		return signature.getSigningCertificateId();
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
		return signature.getCertificateChainIds();
	}

	public String getPolicyId() {
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
		return timestamp.getSigningCertificateId();
	}

	public String getTimestampType(String timestampId) {
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
		return certificate.isValidCertificate();
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
	 * This method returns the associated TSPServiceName.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return TSPServiceName
	 */
	public String getCertificateTSPServiceName(final String dssCertificateId) {
		CertificateWrapper certificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		return certificate.getCertificateTSPServiceName();
	}

	public String getCertificateTSPServiceType(XmlCertificate xmlCertificate) {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = xmlCertificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType trustedServiceProvider : trustedServiceProviders) {
				return trustedServiceProvider.getTSPServiceType(); // TODO correct ?? return first one
			}
		}
		return StringUtils.EMPTY;
	}

	/**
	 * This method indicates if the associated trusted list is well signed.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return TSPServiceName
	 */
	public boolean isCertificateRelatedTSLWellSigned(final String dssCertificateId) {
		CertificateWrapper certificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		return certificate.isCertificateRelatedTSLWellSigned();
	}

	/**
	 * This method returns the revocation source for the given certificate.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return revocation source
	 */
	public String getCertificateRevocationSource(final String dssCertificateId) {
		CertificateWrapper certificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		if (certificate.isRevocationDataAvailable()) {
			return certificate.getLatestRevocationData().getSource();
		}
		return StringUtils.EMPTY;
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
			return certificate.getLatestRevocationData().isStatus();
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
	public String getCertificateRevocationReason(String dssCertificateId) {
		CertificateWrapper certificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		if (certificate.isRevocationDataAvailable()) {
			return certificate.getLatestRevocationData().getReason();
		}
		return StringUtils.EMPTY;
	}

	public String getErrorMessage(final String signatureId) {
		SignatureWrapper signature = getSignatureByIdNullSafe(signatureId);
		return signature.getErrorMessage();
	}

	private SignatureWrapper getFirstSignatureNullSafe() {
		List<SignatureWrapper> signatures = getSignatures();
		if (CollectionUtils.isNotEmpty(signatures)) {
			return signatures.get(0);
		}
		return new SignatureWrapper(new XmlSignature()); // TODO improve ?
	}

	public SignatureWrapper getSignatureById(String id) {
		List<SignatureWrapper> signatures = getSignatures();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (SignatureWrapper xmlSignature : signatures) {
				if (StringUtils.equals(id, xmlSignature.getId())) {
					return xmlSignature;
				}
			}
		}
		return null;
	}

	private SignatureWrapper getSignatureByIdNullSafe(String id) {
		List<SignatureWrapper> signatures = getSignatures();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (SignatureWrapper xmlSignature : signatures) {
				if (StringUtils.equals(id, xmlSignature.getId())) {
					return xmlSignature;
				}
			}
		}
		return new SignatureWrapper(new XmlSignature()); // TODO improve ?
	}

	private TimestampWrapper getTimestampByIdNullSafe(String id) {
		List<SignatureWrapper> signatures = getSignatures();
		for (SignatureWrapper signatureWrapper : signatures) {
			List<TimestampWrapper> timestampList = signatureWrapper.getTimestampList();
			for (TimestampWrapper timestampWrapper : timestampList) {
				if (StringUtils.equals(id, timestampWrapper.getId())) {
					return timestampWrapper;
				}
			}
		}
		return new TimestampWrapper(new XmlTimestampType());
	}

	public CertificateWrapper getUsedCertificateByIdNullSafe(String id) {
		List<CertificateWrapper> certificates = getUsedCertificates();
		if (CollectionUtils.isNotEmpty(certificates)) {
			for (CertificateWrapper certificate : certificates) {
				if (StringUtils.equals(id, certificate.getId())) {
					return certificate;
				}
			}
		}
		return new CertificateWrapper(new XmlCertificate()); // TODO improve ?
	}

	public CertificateWrapper getUsedCertificateById(String id) {
		List<CertificateWrapper> certificates = getUsedCertificates();
		if (CollectionUtils.isNotEmpty(certificates)) {
			for (CertificateWrapper certificate : certificates) {
				if (StringUtils.equals(id, certificate.getId())) {
					return certificate;
				}
			}
		}
		return null;
	}

	public List<SignatureWrapper> getSignatures() {
		if (foundSignatures == null) {
			foundSignatures = new ArrayList<SignatureWrapper>();
			List<XmlSignature> xmlSignatures = diagnosticData.getSignature();
			if (CollectionUtils.isNotEmpty(xmlSignatures)) {
				for (XmlSignature xmlSignature : xmlSignatures) {
					foundSignatures.add(new SignatureWrapper(xmlSignature));
				}
			}
		}
		return foundSignatures;
	}

	public List<CertificateWrapper> getUsedCertificates() {
		if (usedCertificates == null) {
			usedCertificates = new ArrayList<CertificateWrapper>();
			XmlUsedCertificates xmlCertificates = diagnosticData.getUsedCertificates();
			if ((xmlCertificates != null) && CollectionUtils.isNotEmpty(xmlCertificates.getCertificate())) {
				for (XmlCertificate certificate : xmlCertificates.getCertificate()) {
					usedCertificates.add(new CertificateWrapper(certificate));
				}
			}
		}
		return usedCertificates;
	}

	/**
	 * This method returns signatures (not countersignatures)
	 * 
	 * @return
	 */
	public Set<SignatureWrapper> getAllSignatures() {
		Set<SignatureWrapper> signatures = new HashSet<SignatureWrapper>();
		List<SignatureWrapper> mixedSignatures = getSignatures();
		for (SignatureWrapper signatureWrapper : mixedSignatures) {
			if (StringUtils.isEmpty(signatureWrapper.getParentId())) {
				signatures.add(signatureWrapper);
			}
		}
		return signatures;
	}

	/**
	 * This method returns counter-signatures (not signatures)
	 * 
	 * @return
	 */
	public Set<SignatureWrapper> getAllCounterSignatures() {
		Set<SignatureWrapper> signatures = new HashSet<SignatureWrapper>();
		List<SignatureWrapper> mixedSignatures = getSignatures();
		for (SignatureWrapper signatureWrapper : mixedSignatures) {
			if (StringUtils.isNotEmpty(signatureWrapper.getParentId())) {
				signatures.add(signatureWrapper);
			}
		}
		return signatures;
	}

	public Set<RevocationWrapper> getAllRevocationData() {
		Set<RevocationWrapper> revocationData = new HashSet<RevocationWrapper>();
		List<CertificateWrapper> certificates = getUsedCertificates();
		if (CollectionUtils.isNotEmpty(certificates)) {
			for (CertificateWrapper certificate : certificates) {
				Set<RevocationWrapper> revocations = certificate.getRevocationData();
				if (revocations != null) {
					revocationData.addAll(revocations);
				}
			}
		}
		return revocationData;
	}

	public Set<TimestampWrapper> getAllTimestampsNotArchival() {
		Set<TimestampWrapper> notArchivalTimestamps = new HashSet<TimestampWrapper>();
		List<SignatureWrapper> signatures = getSignatures();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (SignatureWrapper signatureWrapper : signatures) {
				notArchivalTimestamps.addAll(signatureWrapper.getAllTimestampsNotArchival());
			}
		}
		return notArchivalTimestamps;
	}

	public Set<TimestampWrapper> getAllTimestampsNotArchival(String signatureId) {
		SignatureWrapper signature = getSignatureById(signatureId);
		if (signature != null) {
			return signature.getAllTimestampsNotArchival();
		}
		return new HashSet<TimestampWrapper>();
	}

	public Set<TimestampWrapper> getAllArchiveTimestamps() {
		Set<TimestampWrapper> archivalTimestamps = new HashSet<TimestampWrapper>();
		List<SignatureWrapper> signatures = getSignatures();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (SignatureWrapper signatureWrapper : signatures) {
				archivalTimestamps.addAll(signatureWrapper.getTimestampListByType(TimestampType.ARCHIVE_TIMESTAMP));
			}
		}
		return archivalTimestamps;
	}

	public Set<TimestampWrapper> getAllTimestamps() {
		Set<TimestampWrapper> allTimestamps = new HashSet<TimestampWrapper>();
		List<SignatureWrapper> signatures = getSignatures();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (SignatureWrapper signatureWrapper : signatures) {
				allTimestamps.addAll(signatureWrapper.getTimestampList());
			}
		}
		return allTimestamps;
	}

	public eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData getJaxbModel() {
		return diagnosticData;
	}

}
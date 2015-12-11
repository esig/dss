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
package eu.europa.esig.dss.validation.report;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.EncryptionAlgorithm;
import eu.europa.esig.dss.TSLConstant;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateChainType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgAndValueType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDistinguishedName;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlQualifiers;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificateType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestampType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTimestamps;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProviderType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlUsedCertificates;
import eu.europa.esig.dss.validation.CertificateWrapper;
import eu.europa.esig.dss.validation.SignatureWrapper;
import eu.europa.esig.dss.x509.TimestampType;

/**
 * This class represents all static data extracted by the process analysing the signature. They are independent from the validation policy to be applied.
 */
public class DiagnosticDataWrapper {

	private final DiagnosticData diagnosticData;

	public DiagnosticDataWrapper(final DiagnosticData diagnosticData) {
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
		XmlSignature firstSignature = getFirstSignatureNullSafe();
		return firstSignature.getId();
	}

	public Date getSignatureDate() {
		XmlSignature firstSignature = getFirstSignatureNullSafe();
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
		XmlSignature xmlSignature = getSignatureByIdNullSafe(signatureId);
		return xmlSignature.getDateTime();
	}

	/**
	 * This method returns the signature format for the given signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature, for which the format is sought.
	 * @return The signature format
	 */
	public String getSignatureFormat(final String signatureId) {
		XmlSignature xmlSignature = getSignatureByIdNullSafe(signatureId);
		return xmlSignature.getSignatureFormat();
	}

	/**
	 * This method returns the {@code DigestAlgorithm} of the first signature.
	 *
	 * @return The {@code DigestAlgorithm} of the first signature
	 */
	public DigestAlgorithm getSignatureDigestAlgorithm() {
		XmlSignature xmlSignature = getFirstSignatureNullSafe();
		return getDigestAlgorithm(xmlSignature);
	}

	/**
	 * This method returns the {@code DigestAlgorithm} for the given signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature, for which the algorithm is sought.
	 * @return The {@code DigestAlgorithm} for the given signature
	 */
	public DigestAlgorithm getSignatureDigestAlgorithm(final String signatureId) {
		XmlSignature xmlSignature = getSignatureByIdNullSafe(signatureId);
		return getDigestAlgorithm(xmlSignature);
	}

	private DigestAlgorithm getDigestAlgorithm(XmlSignature xmlSignature) {
		String signatureDigestAlgorithmName = StringUtils.EMPTY;
		if (xmlSignature.getBasicSignature() != null) {
			signatureDigestAlgorithmName = xmlSignature.getBasicSignature().getDigestAlgoUsedToSignThisToken();
		}
		return DigestAlgorithm.forName(signatureDigestAlgorithmName, null);
	}

	/**
	 * This method returns the {@code EncryptionAlgorithm} of the first signature.
	 *
	 * @return The {@code EncryptionAlgorithm} of the first signature
	 */
	public EncryptionAlgorithm getSignatureEncryptionAlgorithm() {
		XmlSignature xmlSignature = getFirstSignatureNullSafe();
		return getEncryptionAlgorithm(xmlSignature);
	}

	/**
	 * This method returns the {@code DigestAlgorithm} for the given signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature, for which the algorithm is sought.
	 * @return The {@code DigestAlgorithm} for the given signature
	 */
	public EncryptionAlgorithm getSignatureEncryptionAlgorithm(final String signatureId) {
		XmlSignature xmlSignature = getSignatureByIdNullSafe(signatureId);
		return getEncryptionAlgorithm(xmlSignature);
	}

	private EncryptionAlgorithm getEncryptionAlgorithm(XmlSignature xmlSignature) {
		String signatureEncryptionAlgorithmName = StringUtils.EMPTY;
		if (xmlSignature.getBasicSignature() != null) {
			signatureEncryptionAlgorithmName = xmlSignature.getBasicSignature().getEncryptionAlgoUsedToSignThisToken();
		}
		return EncryptionAlgorithm.forName(signatureEncryptionAlgorithmName, null);
	}

	/**
	 * This method returns signing certificate dss id for the first signature.
	 *
	 * @return signing certificate dss id.
	 */
	public String getSigningCertificateId() {
		XmlSignature xmlSignature = getFirstSignatureNullSafe();
		return getSigningCertificateId(xmlSignature);
	}

	/**
	 * This method returns signing certificate dss id for the given signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature, for which the signing certificate is sought.
	 * @return signing certificate dss id for the given signature.
	 */
	public String getSigningCertificateId(final String signatureId) {
		XmlSignature xmlSignature = getSignatureByIdNullSafe(signatureId);
		return getSigningCertificateId(xmlSignature);
	}

	private String getSigningCertificateId(XmlSignature xmlSignature) {
		XmlSigningCertificateType signingCertificate = xmlSignature.getSigningCertificate();
		if (signingCertificate != null) {
			return signingCertificate.getId();
		}
		return StringUtils.EMPTY;
	}

	/**
	 * This method indicates if the digest value and the issuer and serial match for the signing certificate .
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the digest value and the issuer and serial match.
	 */
	public boolean isSigningCertificateIdentified(final String signatureId) {
		XmlSignature xmlSignature = getSignatureByIdNullSafe(signatureId);
		XmlSigningCertificateType signingCertificate = xmlSignature.getSigningCertificate();
		if (signingCertificate != null) {
			return signingCertificate.isDigestValueMatch() && signingCertificate.isIssuerSerialMatch();
		}
		return false;
	}

	/**
	 * This method returns the list of certificates in the chain of the main signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return list of certificate's dss id for the given signature.
	 */
	public List<String> getSignatureCertificateChain(final String signatureId) {
		List<String> result = new ArrayList<String>();
		XmlSignature xmlSignature = getSignatureByIdNullSafe(signatureId);
		XmlCertificateChainType certificateChain = xmlSignature.getCertificateChain();
		if ((certificateChain != null) && CollectionUtils.isNotEmpty(certificateChain.getChainCertificate())) {
			for (XmlChainCertificate certificate : certificateChain.getChainCertificate()) {
				result.add(certificate.getId());
			}
		}
		return result;
	}

	public String getPolicyId() {
		XmlSignature xmlSignature = getFirstSignatureNullSafe();
		return getPolicyId(xmlSignature);
	}

	/**
	 * The identifier of the policy.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return the policy identifier
	 */
	public String getPolicyId(final String signatureId) {
		XmlSignature xmlSignature = getSignatureByIdNullSafe(signatureId);
		return getPolicyId(xmlSignature);
	}

	private String getPolicyId(XmlSignature xmlSignature) {
		XmlPolicy policy = xmlSignature.getPolicy();
		if (policy != null) {
			return policy.getId();
		}
		return StringUtils.EMPTY;
	}

	/**
	 * This method returns the list of identifier of the timestamps related to the given signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return The list of identifier of the timestamps
	 */
	public List<String> getTimestampIdList(final String signatureId) {
		List<String> result = new ArrayList<String>();
		XmlSignature xmlSignature = getSignatureByIdNullSafe(signatureId);
		XmlTimestamps timestamps = xmlSignature.getTimestamps();
		if ((timestamps != null) && CollectionUtils.isNotEmpty(timestamps.getTimestamp())) {
			for (XmlTimestampType xmlTsp : timestamps.getTimestamp()) {
				result.add(xmlTsp.getId());
			}
		}
		return result;
	}

	/**
	 * This method returns the list of identifier of the timestamps related to the given signature.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @param timestampType
	 *            The {@code TimestampType}
	 * @return The list of identifier of the timestamps
	 */
	public List<String> getTimestampIdList(final String signatureId, final TimestampType timestampType) {
		List<String> result = new ArrayList<String>();
		List<XmlTimestampType> timestampList = getTimestampList(signatureId, timestampType);
		if (CollectionUtils.isNotEmpty(timestampList)) {
			for (XmlTimestampType xmlTsp : timestampList) {
				result.add(xmlTsp.getId());
			}
		}
		return result;
	}

	public List<XmlTimestampType> getTimestampList(final String signatureId) {
		List<XmlTimestampType> result = new ArrayList<XmlTimestampType>();
		XmlSignature xmlSignature = getSignatureByIdNullSafe(signatureId);
		XmlTimestamps timestamps = xmlSignature.getTimestamps();
		if ((timestamps != null) && CollectionUtils.isNotEmpty(timestamps.getTimestamp())) {
			for (XmlTimestampType xmlTsp : timestamps.getTimestamp()) {
				result.add(xmlTsp);
			}
		}
		return result;
	}

	/**
	 * Indicates if the -B level is technically valid. It means that the signature value is valid.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the signature value is valid
	 */
	public boolean isBLevelTechnicallyValid(final String signatureId) {
		XmlSignature xmlSignature = getSignatureByIdNullSafe(signatureId);
		return (xmlSignature.getBasicSignature() != null) && xmlSignature.getBasicSignature().isSignatureValid();
	}

	/**
	 * Indicates if there is a signature timestamp.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the signature timestamp is present
	 */
	public boolean isThereTLevel(final String signatureId) {
		List<String> timestampIdList = getTimestampIdList(signatureId, TimestampType.SIGNATURE_TIMESTAMP);
		return timestampIdList.size() > 0;
	}

	/**
	 * Indicates if the -T level is technically valid. It means that the signature and the digest are valid.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the signature and digest are valid
	 */
	public boolean isTLevelTechnicallyValid(final String signatureId) {
		List<XmlTimestampType> timestampList = getTimestampList(signatureId, TimestampType.SIGNATURE_TIMESTAMP);
		return isTimestampValid(timestampList);
	}

	private boolean isTimestampValid(List<XmlTimestampType> timestampList) {
		for (final XmlTimestampType timestamp : timestampList) {
			final boolean signatureValid = (timestamp.getBasicSignature() != null) && timestamp.getBasicSignature().isSignatureValid();
			final boolean messageImprintIntact = timestamp.isMessageImprintDataIntact();
			if (signatureValid && messageImprintIntact) { // TODO correct ?  return true if at least 1 TSP OK
				return true;
			}
		}
		return false;
	}

	/**
	 * Indicates if there is an -X1 or -X2 timestamp.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the -X1 or -X2 is present
	 */
	public boolean isThereXLevel(final String signatureId) {
		List<XmlTimestampType> vdroTimestamps = getTimestampList(signatureId, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
		List<XmlTimestampType> vdTimestamps = getTimestampList(signatureId, TimestampType.VALIDATION_DATA_TIMESTAMP);
		return (vdroTimestamps.size() > 0) || (vdTimestamps.size() > 0);
	}

	/**
	 * Indicates if the -X level is technically valid. It means that the signature and the digest are valid.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the signature and digest are valid
	 */
	public boolean isXLevelTechnicallyValid(final String signatureId) {
		List<XmlTimestampType> timestamps = getTimestampList(signatureId, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
		timestamps.addAll(getTimestampList(signatureId, TimestampType.VALIDATION_DATA_TIMESTAMP));
		return isTimestampValid(timestamps);
	}

	/**
	 * Indicates if there is an archive timestamp.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the archive timestamp is present
	 */
	public boolean isThereALevel(final String signatureId) {
		List<XmlTimestampType> timestampList = getTimestampList(signatureId, TimestampType.ARCHIVE_TIMESTAMP);
		return timestampList.size() > 0;
	}

	/**
	 * Indicates if the -A (-LTA) level is technically valid. It means that the signature of the archive timestamps are valid and their imprint is valid too.
	 *
	 * @param signatureId
	 *            The identifier of the signature.
	 * @return true if the signature and digest are valid
	 */
	public boolean isALevelTechnicallyValid(final String signatureId) {
		List<XmlTimestampType> timestampList = getTimestampList(signatureId, TimestampType.ARCHIVE_TIMESTAMP);
		return isTimestampValid(timestampList);
	}

	/**
	 * Returns the identifier of the timestamp signing certificate.
	 *
	 * @param timestampId
	 *            timestamp id
	 * @return signing certificate id
	 */
	public String getTimestampSigningCertificateId(final String timestampId) {
		XmlTimestampType timestamp = getTimestampByIdNullSafe(timestampId);
		XmlSigningCertificateType signingCertificate = timestamp.getSigningCertificate();
		if (signingCertificate != null) {
			return signingCertificate.getId();
		}
		return StringUtils.EMPTY;
	}

	/**
	 * Returns the digest algorithm used to compute the hash value.
	 *
	 * @param timestampId
	 *            timestamp id
	 * @return the digest algorithm
	 */
	public Date getTimestampProductionTime(final String timestampId) {
		XmlTimestampType timestamp = getTimestampByIdNullSafe(timestampId);
		return timestamp.getProductionTime();
	}

	/**
	 * Returns the digest algorithm used to compute the hash value.
	 *
	 * @param timestampId
	 *            timestamp id
	 * @return the digest algorithm
	 */
	public String getTimestampDigestAlgorithm(final String timestampId) {
		XmlTimestampType timestamp = getTimestampByIdNullSafe(timestampId);
		return timestamp.getSignedDataDigestAlgo(); // TODO enum ?
	}

	/**
	 * Returns the result of validation of the timestamp message imprint.
	 *
	 * @param timestampId
	 *            timestamp id
	 * @return true or false
	 */
	public boolean isTimestampMessageImprintIntact(final String timestampId) {
		XmlTimestampType timestamp = getTimestampByIdNullSafe(timestampId);
		return timestamp.isMessageImprintDataIntact();
	}

	/**
	 * Returns the result of validation of the timestamp signature.
	 *
	 * @param timestampId
	 *            timestamp id
	 * @return
	 */
	public boolean isTimestampSignatureValid(final String timestampId) {
		XmlTimestampType timestamp = getTimestampByIdNullSafe(timestampId);
		return (timestamp.getBasicSignature() != null) && timestamp.getBasicSignature().isSignatureValid();
	}

	/**
	 * Returns the type of the timestamp.
	 *
	 * @param timestampId
	 *            timestamp id
	 * @return
	 */
	public String getTimestampType(final String timestampId) {
		XmlTimestampType timestamp = getTimestampByIdNullSafe(timestampId);
		return timestamp.getType(); // TODO enum ?
	}

	public String getTimestampCanonicalizationMethod(final String timestampId) {
		XmlTimestampType timestamp = getTimestampByIdNullSafe(timestampId);
		return timestamp.getCanonicalizationMethod();
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
		XmlCertificate xmlCertificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		return getFormat(xmlCertificate.getSubjectDistinguishedName(), "RFC2253");
	}

	/**
	 * This method returns the issuer distinguished name for the given dss certificate identifier.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return issuer distinguished name
	 */
	public String getCertificateIssuerDN(final String dssCertificateId) {
		XmlCertificate xmlCertificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		return getFormat(xmlCertificate.getIssuerDistinguishedName(), "RFC2253");
	}

	private String getFormat(List<XmlDistinguishedName> distinguishedNames, String format) {
		if (CollectionUtils.isNotEmpty(distinguishedNames)) {
			for (XmlDistinguishedName distinguishedName : distinguishedNames) {
				if (StringUtils.equals(distinguishedName.getFormat(), format)) {
					return distinguishedName.getValue();
				}
			}
		}
		return StringUtils.EMPTY;
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
	 * This method indicates if the certificate has QCWithSSCD qualification.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return true if QCWithSSCD qualification is present
	 */
	public boolean hasCertificateQCWithSSCDQualification(final String dssCertificateId) {
		XmlCertificate xmlCertificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		List<String> expectedQualifications = new ArrayList<String>();
		expectedQualifications.add(TSLConstant.QC_WITH_SSCD);
		expectedQualifications.add(TSLConstant.QC_WITH_SSCD_119612);
		return hasQualification(xmlCertificate, expectedQualifications);
	}

	/**
	 * This method indicates if the certificate has QCNoSSCD qualification.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return true if QCNoSSCD qualification is present
	 */
	public boolean hasCertificateQCNoSSCDQualification(final String dssCertificateId) {
		XmlCertificate xmlCertificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		List<String> expectedQualifications = new ArrayList<String>();
		expectedQualifications.add(TSLConstant.QC_NO_SSCD);
		expectedQualifications.add(TSLConstant.QC_NO_SSCD_119612);
		return hasQualification(xmlCertificate, expectedQualifications);
	}

	/**
	 * This method indicates if the certificate has QCSSCDStatusAsInCert qualification.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return true if QCSSCDStatusAsInCert qualification is present
	 */
	public boolean hasCertificateQCSSCDStatusAsInCertQualification(final String dssCertificateId) {
		XmlCertificate xmlCertificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		List<String> expectedQualifications = new ArrayList<String>();
		expectedQualifications.add(TSLConstant.QCSSCD_STATUS_AS_IN_CERT);
		expectedQualifications.add(TSLConstant.QCSSCD_STATUS_AS_IN_CERT_119612);
		return hasQualification(xmlCertificate, expectedQualifications);
	}

	/**
	 * This method indicates if the certificate has QCForLegalPerson qualification.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return true if QCForLegalPerson qualification is present
	 */
	public boolean hasCertificateQCForLegalPersonQualification(final String dssCertificateId) {
		XmlCertificate xmlCertificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		List<String> expectedQualifications = new ArrayList<String>();
		expectedQualifications.add(TSLConstant.QC_FOR_LEGAL_PERSON);
		expectedQualifications.add(TSLConstant.QC_FOR_LEGAL_PERSON_119612);
		return hasQualification(xmlCertificate, expectedQualifications);
	}

	private boolean hasQualification(XmlCertificate xmlCertificate, List<String> expectedQualifications) {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = xmlCertificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType xmlTrustedServiceProvider : trustedServiceProviders) {
				XmlQualifiers qualifiers = xmlTrustedServiceProvider.getQualifiers();
				if ((qualifiers != null) && CollectionUtils.isNotEmpty(qualifiers.getQualifier())) {
					for (String qualifier : qualifiers.getQualifier()) {
						if (expectedQualifications.contains(qualifier)) {
							return true;
						}
					}
				}
			}
		}
		return false;
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

	public String getCertificateTSPServiceStatus(final String dssCertificateId) {
		CertificateWrapper certificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		return certificate.getCertificateTSPServiceStatus();
	}

	public Date getCertificateTSPServiceStartDate(final String dssCertificateId) {
		CertificateWrapper certificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		return certificate.getCertificateTSPServiceStartDate();
	}

	public Date getCertificateTSPServiceEndDate(final String dssCertificateId) {
		CertificateWrapper certificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		return certificate.getCertificateTSPServiceEndDate();
	}

	public List<XmlTrustedServiceProviderType> getCertificateTSPService(final String dssCertificateId) {
		XmlCertificate xmlCertificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		return getCertificateTSPService(xmlCertificate);
	}

	public List<XmlTrustedServiceProviderType> getCertificateTSPService(XmlCertificate xmlCertificate) {
		return xmlCertificate.getTrustedServiceProvider();
	}

	/**
	 * This method indicates if the associated trusted list is well signed.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return TSPServiceName
	 */
	public boolean isCertificateRelatedTSLWellSigned(final String dssCertificateId) {
		XmlCertificate xmlCertificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		List<XmlTrustedServiceProviderType> trustedServiceProviders = xmlCertificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			boolean isWellSigned = true;
			for (XmlTrustedServiceProviderType xmlTrustedServiceProviderType : trustedServiceProviders) {
				isWellSigned &= xmlTrustedServiceProviderType.isWellSigned();
			}
			return isWellSigned;
		}
		return false;
		// TODO correct ???
		//		final boolean wellSigned = getBoolValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/TrustedServiceProvider/WellSigned/text()", dssCertificateId);
		//		return wellSigned;
	}

	/**
	 * This method returns the revocation source for the given certificate.
	 *
	 * @param dssCertificateId
	 *            DSS certificate identifier to be checked
	 * @return revocation source
	 */
	public String getCertificateRevocationSource(final String dssCertificateId) {
		XmlCertificate xmlCertificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		XmlRevocationType revocation = xmlCertificate.getRevocation();
		if (revocation != null) {
			return revocation.getSource();
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
		XmlCertificate xmlCertificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		XmlRevocationType revocation = xmlCertificate.getRevocation();
		if (revocation != null) {
			return revocation.isStatus();
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
		XmlCertificate xmlCertificate = getUsedCertificateByIdNullSafe(dssCertificateId);
		XmlRevocationType revocation = xmlCertificate.getRevocation();
		if (revocation != null) {
			return revocation.getReason();
		}
		return StringUtils.EMPTY;
	}

	public String getErrorMessage(final String signatureId) {
		XmlSignature xmlSignature = getSignatureByIdNullSafe(signatureId);
		return xmlSignature.getErrorMessage();
	}

	private XmlSignature getFirstSignatureNullSafe() {
		List<XmlSignature> signatures = diagnosticData.getSignature();
		if (CollectionUtils.isNotEmpty(signatures)) {
			return signatures.get(0);
		}
		return new XmlSignature();
	}

	private XmlSignature getSignatureByIdNullSafe(String id) {
		List<XmlSignature> signatures = diagnosticData.getSignature();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (XmlSignature xmlSignature : signatures) {
				if (StringUtils.equals(id, xmlSignature.getId())) {
					return xmlSignature;
				}
			}
		}
		return new XmlSignature();
	}

	private XmlTimestampType getTimestampByIdNullSafe(String id) {
		List<XmlSignature> signatures = diagnosticData.getSignature();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (XmlSignature xmlSignature : signatures) {
				XmlTimestamps timestamps = xmlSignature.getTimestamps();
				if ((timestamps != null) && CollectionUtils.isNotEmpty(timestamps.getTimestamp())) {
					for (XmlTimestampType tsp : timestamps.getTimestamp()) {
						if (StringUtils.equals(id, tsp.getId())) {
							return tsp;
						}
					}
				}
			}
		}
		return new XmlTimestampType();
	}

	public CertificateWrapper getUsedCertificateByIdNullSafe(String id) {
		XmlUsedCertificates usedCertificates = diagnosticData.getUsedCertificates();
		if ((usedCertificates != null) && CollectionUtils.isNotEmpty(usedCertificates.getCertificate())) {
			for (XmlCertificate xmlCertificate : usedCertificates.getCertificate()) {
				if (StringUtils.equals(id, xmlCertificate.getId())) {
					return new CertificateWrapper(xmlCertificate);
				}
			}
		}
		return new CertificateWrapper(new XmlCertificate()); // TODO improve ?
	}

	public XmlCertificate getUsedCertificateByDigest(String digestMethod, String digestValue) {
		XmlUsedCertificates usedCertificates = diagnosticData.getUsedCertificates();
		if ((usedCertificates != null) && CollectionUtils.isNotEmpty(usedCertificates.getCertificate())) {
			for (XmlCertificate xmlCertificate : usedCertificates.getCertificate()) {
				List<XmlDigestAlgAndValueType> digestAlgAndValues = xmlCertificate.getDigestAlgAndValue();
				if (CollectionUtils.isNotEmpty(digestAlgAndValues)) {
					for (XmlDigestAlgAndValueType digestAlgAndValue : digestAlgAndValues) {
						if (StringUtils.equals(digestMethod, digestAlgAndValue.getDigestMethod()) && StringUtils.equals(digestValue, digestAlgAndValue.getDigestValue())) {
							return xmlCertificate;
						}
					}
				}
			}
		}
		return null;
	}

	public List<SignatureWrapper> getSignatures() {
		List<SignatureWrapper> result = new ArrayList<SignatureWrapper>();
		List<XmlSignature> signatures = diagnosticData.getSignature();
		if (CollectionUtils.isNotEmpty(signatures)) {
			for (XmlSignature xmlSignature : signatures) {
				result.add(new SignatureWrapper(xmlSignature));
			}
		}
		return result;
	}

	public boolean isRevocationDataExists(XmlCertificate certificate) {
		return (certificate != null) && (certificate.getRevocation() != null);
	}

	public Date getRevocationIssuingDate(XmlCertificate certificate) {
		if ((certificate != null) && (certificate.getRevocation() != null)) {
			return certificate.getRevocation().getIssuingTime();
		}
		return null;
	}

	public List<XmlCertificate> getUsedCertificates() {
		XmlUsedCertificates usedCertificates = diagnosticData.getUsedCertificates();
		return usedCertificates.getCertificate();
	}

}
package eu.europa.esig.dss.validation.reports.wrapper;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignatureType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateChainType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgAndValueType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDistinguishedName;
import eu.europa.esig.dss.jaxb.diagnostic.XmlKeyUsageBits;
import eu.europa.esig.dss.jaxb.diagnostic.XmlQCStatement;
import eu.europa.esig.dss.jaxb.diagnostic.XmlQualifiers;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificateType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProviderType;
import eu.europa.esig.dss.validation.policy.TSLConstant;

public class CertificateWrapper extends AbstractTokenProxy {

	private final XmlCertificate certificate;

	public CertificateWrapper(XmlCertificate certificate) {
		this.certificate = certificate;
	}

	@Override
	public String getId() {
		return certificate.getId();
	}

	@Override
	protected XmlBasicSignatureType getCurrentBasicSignature() {
		return certificate.getBasicSignature();
	}

	@Override
	protected XmlCertificateChainType getCurrentCertificateChain() {
		return certificate.getCertificateChain();
	}

	@Override
	protected XmlSigningCertificateType getCurrentSigningCertificate() {
		return certificate.getSigningCertificate();
	}

	public boolean isTrusted() {
		return certificate.isTrusted();
	}

	public List<String> getKeyUsages() {
		List<String> keyUsages = new ArrayList<String>();
		XmlKeyUsageBits keyUsageBits = certificate.getKeyUsageBits();
		if ((keyUsageBits != null) && CollectionUtils.isNotEmpty(keyUsageBits.getKeyUsage())) {
			keyUsages.addAll(keyUsageBits.getKeyUsage());
		}
		return keyUsages;
	}

	public boolean isRevocationDataAvailable() {
		return certificate.getRevocation() != null;
	}

	public RevocationWrapper getRevocationData() {
		if (isRevocationDataAvailable()) {
			return new RevocationWrapper(certificate.getRevocation());
		}
		return null;
	}

	public boolean isIdPkixOcspNoCheck() {
		return BooleanUtils.isTrue(certificate.isIdPkixOcspNoCheck());
	}

	public boolean isIdKpOCSPSigning() {
		return BooleanUtils.isTrue(certificate.isIdKpOCSPSigning());
	}

	public Date getNotBefore() {
		return certificate.getNotBefore();
	}

	public Date getNotAfter() {
		return certificate.getNotAfter();
	}

	public boolean isCertificateQCP() {
		XmlQCStatement qcStatement = certificate.getQCStatement();
		return (qcStatement != null) && qcStatement.isQCP();
	}

	public boolean isCertificateQCPPlus() {
		XmlQCStatement qcStatement = certificate.getQCStatement();
		return (qcStatement != null) && qcStatement.isQCPPlus();
	}

	public boolean isCertificateQCC() {
		XmlQCStatement qcStatement = certificate.getQCStatement();
		return (qcStatement != null) && qcStatement.isQCC();
	}

	public boolean isCertificateQCSSCD() {
		XmlQCStatement qcStatement = certificate.getQCStatement();
		return (qcStatement != null) && qcStatement.isQCSSCD();
	}

	public List<String> getCertificateTSPServiceQualifiers() {
		Set<String> result = new HashSet<String>();
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType xmlTrustedServiceProvider : trustedServiceProviders) {
				XmlQualifiers qualifiers = xmlTrustedServiceProvider.getQualifiers();
				if ((qualifiers != null) && CollectionUtils.isNotEmpty(qualifiers.getQualifier())) {
					for (String qualifier : qualifiers.getQualifier()) {
						result.add(qualifier);
					}
				}
			}
		}
		return new ArrayList<String>(result);
	}

	public String getCertificateTSPServiceStatus() {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType trustedServiceProvider : trustedServiceProviders) {
				return trustedServiceProvider.getStatus(); // TODO correct ?? return first one
			}
		}
		return StringUtils.EMPTY;
	}

	public Date getCertificateTSPServiceStartDate() {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType trustedServiceProvider : trustedServiceProviders) {
				return trustedServiceProvider.getStartDate(); // TODO correct ?? return first one
			}
		}
		return null;
	}

	public Date getCertificateTSPServiceEndDate() {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType trustedServiceProvider : trustedServiceProviders) {
				return trustedServiceProvider.getEndDate(); // TODO correct ?? return first one
			}
		}
		return null;
	}

	public Date getCertificateTSPServiceExpiredCertsRevocationInfo() {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType trustedServiceProvider : trustedServiceProviders) {
				return trustedServiceProvider.getExpiredCertsRevocationInfo(); // TODO correct ?? return first one
			}
		}
		return null;
	}

	public String getCertificateTSPServiceName() {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType trustedServiceProvider : trustedServiceProviders) {
				return trustedServiceProvider.getTSPServiceName(); // TODO correct ?? return first one
			}
		}
		return StringUtils.EMPTY;
	}

	public String getCertificateTSPServiceType() {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType trustedServiceProvider : trustedServiceProviders) {
				return trustedServiceProvider.getTSPServiceType(); // TODO correct ?? return first one
			}
		}
		return StringUtils.EMPTY;
	}

	public boolean isRevoked() {
		if ((certificate != null) && (certificate.getRevocation() != null)) {
			return certificate.getRevocation().isStatus() && certificate.getRevocation().getRevocationDate() != null;
		}
		return false;
	}

	public boolean isValidCertificate() {
		final boolean signatureValid = (certificate.getBasicSignature() != null) && certificate.getBasicSignature().isSignatureValid();
		final boolean revocationValid = (certificate.getRevocation() != null) && certificate.getRevocation().isStatus();
		final boolean trusted = certificate.isTrusted();

		final boolean validity = signatureValid && (trusted ? true : revocationValid);
		return validity;
	}

	public String getSerialNumber() {
		BigInteger serialNumber = certificate.getSerialNumber();
		return serialNumber == null ? StringUtils.EMPTY : serialNumber.toString();
	}

	public String getCommonName() {
		String cn = certificate.getCommonName();
		return cn == null ? StringUtils.EMPTY : cn;
	}

	public String getCountryName() {
		String c = certificate.getCountryName();
		return c == null ? StringUtils.EMPTY : c;
	}

	public String getGivenName() {
		String givenName = certificate.getGivenName();
		return givenName == null ? StringUtils.EMPTY : givenName;
	}

	public String getOrganizationName() {
		String o = certificate.getOrganizationName();
		return o == null ? StringUtils.EMPTY : o;
	}

	public String getOrganizationalUnit() {
		String ou = certificate.getOrganizationalUnit();
		return ou == null ? StringUtils.EMPTY : ou;
	}

	public String getSurname() {
		String surname = certificate.getSurname();
		return surname == null ? StringUtils.EMPTY : surname;
	}

	public String getPseudo() {
		String pseudo = certificate.getPseudonym();
		return pseudo == null ? StringUtils.EMPTY : pseudo;
	}

	/**
	 * This method indicates if the certificate has QCWithSSCD qualification.
	 *
	 * @return true if QCWithSSCD qualification is present
	 */
	public boolean hasCertificateQCWithSSCDQualification() {
		List<String> expectedQualifications = new ArrayList<String>();
		expectedQualifications.add(TSLConstant.QC_WITH_SSCD);
		expectedQualifications.add(TSLConstant.QC_WITH_SSCD_119612);
		return hasQualification(expectedQualifications);
	}

	/**
	 * This method indicates if the certificate has QCNoSSCD qualification.
	 *
	 * @return true if QCNoSSCD qualification is present
	 */
	public boolean hasCertificateQCNoSSCDQualification() {
		List<String> expectedQualifications = new ArrayList<String>();
		expectedQualifications.add(TSLConstant.QC_NO_SSCD);
		expectedQualifications.add(TSLConstant.QC_NO_SSCD_119612);
		return hasQualification(expectedQualifications);
	}

	/**
	 * This method indicates if the certificate has QCSSCDStatusAsInCert qualification.
	 *
	 * @return true if QCSSCDStatusAsInCert qualification is present
	 */
	public boolean hasCertificateQCSSCDStatusAsInCertQualification() {
		List<String> expectedQualifications = new ArrayList<String>();
		expectedQualifications.add(TSLConstant.QCSSCD_STATUS_AS_IN_CERT);
		expectedQualifications.add(TSLConstant.QCSSCD_STATUS_AS_IN_CERT_119612);
		return hasQualification(expectedQualifications);
	}

	/**
	 * This method indicates if the certificate has QCForLegalPerson qualification.
	 *
	 * @return true if QCForLegalPerson qualification is present
	 */
	public boolean hasCertificateQCForLegalPersonQualification() {
		List<String> expectedQualifications = new ArrayList<String>();
		expectedQualifications.add(TSLConstant.QC_FOR_LEGAL_PERSON);
		expectedQualifications.add(TSLConstant.QC_FOR_LEGAL_PERSON_119612);
		return hasQualification(expectedQualifications);
	}

	private boolean hasQualification(List<String> expectedQualifications) {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
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

	public boolean isCertificateRelatedTSLWellSigned() {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (CollectionUtils.isNotEmpty(trustedServiceProviders)) {
			boolean isWellSigned = true;
			for (XmlTrustedServiceProviderType xmlTrustedServiceProviderType : trustedServiceProviders) {
				isWellSigned &= xmlTrustedServiceProviderType.isWellSigned();
			}
			return isWellSigned;
		}
		return false;
		// TODO correct ???
		// final boolean wellSigned =
		// getBoolValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/TrustedServiceProvider/WellSigned/text()",
		// dssCertificateId);
		// return wellSigned;
	}

	public List<XmlDigestAlgAndValueType> getDigestAlgAndValue() {
		return certificate.getDigestAlgAndValue();
	}

	public List<XmlTrustedServiceProviderType> getCertificateTSPService() {
		return certificate.getTrustedServiceProvider();
	}

	public String getCertificateDN() {
		return getFormat(certificate.getSubjectDistinguishedName(), "RFC2253");
	}

	public String getCertificateIssuerDN() {
		return getFormat(certificate.getIssuerDistinguishedName(), "RFC2253");
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

}

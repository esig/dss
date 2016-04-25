package eu.europa.esig.dss.validation.reports.wrapper;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
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
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificatePolicyIds;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgAndValueType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDistinguishedName;
import eu.europa.esig.dss.jaxb.diagnostic.XmlKeyUsageBits;
import eu.europa.esig.dss.jaxb.diagnostic.XmlQCStatementIds;
import eu.europa.esig.dss.jaxb.diagnostic.XmlQualifiers;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificateType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProviderType;

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

	public List<String> getPolicyIds() {
		XmlCertificatePolicyIds certificatePolicyIds = certificate.getCertificatePolicyIds();
		if (certificatePolicyIds != null) {
			return certificatePolicyIds.getOid();
		} else {
			return Collections.emptyList();
		}
	}

	public List<String> getQCStatementIds() {
		XmlQCStatementIds certificateQCStatementIds = certificate.getQCStatementIds();
		if (certificateQCStatementIds != null) {
			return certificateQCStatementIds.getOid();
		} else {
			return Collections.emptyList();
		}
	}

}

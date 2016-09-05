package eu.europa.esig.dss.validation.reports.wrapper;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignatureType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificateChainType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificatePolicyIds;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgAndValueType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDistinguishedName;
import eu.europa.esig.dss.jaxb.diagnostic.XmlKeyUsageBits;
import eu.europa.esig.dss.jaxb.diagnostic.XmlQCStatementIds;
import eu.europa.esig.dss.jaxb.diagnostic.XmlQualifiers;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocationType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificateType;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProviderType;
import eu.europa.esig.dss.utils.Utils;

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
		if ((keyUsageBits != null) && Utils.isCollectionNotEmpty(keyUsageBits.getKeyUsage())) {
			keyUsages.addAll(keyUsageBits.getKeyUsage());
		}
		return keyUsages;
	}

	public boolean isRevocationDataAvailable() {
		return Utils.isCollectionNotEmpty(certificate.getRevocation());
	}

	public Set<RevocationWrapper> getRevocationData() {
		if (isRevocationDataAvailable()) {
			List<XmlRevocationType> revocation = certificate.getRevocation();
			Set<RevocationWrapper> result = new HashSet<RevocationWrapper>();
			for (XmlRevocationType xmlRevocationType : revocation) {
				result.add(new RevocationWrapper(xmlRevocationType));
			}
			return result;
		}
		return Collections.emptySet();
	}

	public RevocationWrapper getLatestRevocationData() {
		RevocationWrapper latest = null;
		for (RevocationWrapper revoc : getRevocationData()) {
			if (latest == null || (revoc.getProductionDate() != null && revoc.getProductionDate().after(latest.getProductionDate()))) {
				latest = revoc;
			}
		}
		return latest;
	}

	public boolean isIdPkixOcspNoCheck() {
		return Utils.isTrue(certificate.isIdPkixOcspNoCheck());
	}

	public boolean isIdKpOCSPSigning() {
		return Utils.isTrue(certificate.isIdKpOCSPSigning());
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
		if (Utils.isCollectionNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType xmlTrustedServiceProvider : trustedServiceProviders) {
				XmlQualifiers qualifiers = xmlTrustedServiceProvider.getQualifiers();
				if ((qualifiers != null) && Utils.isCollectionNotEmpty(qualifiers.getQualifier())) {
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
		if (Utils.isCollectionNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType trustedServiceProvider : trustedServiceProviders) {
				return trustedServiceProvider.getTSPServiceName(); // TODO correct ?? return first one
			}
		}
		return Utils.EMPTY_STRING;
	}

	public String getCertificateTSPServiceType() {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (Utils.isCollectionNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType trustedServiceProvider : trustedServiceProviders) {
				return trustedServiceProvider.getTSPServiceType(); // TODO correct ?? return first one
			}
		}
		return Utils.EMPTY_STRING;
	}

	public Date getCertificateTSPServiceExpiredCertsRevocationInfo() {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (Utils.isCollectionNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProviderType trustedServiceProvider : trustedServiceProviders) {
				return trustedServiceProvider.getExpiredCertsRevocationInfo();
			}
		}
		return null;
	}

	public boolean isRevoked() {
		RevocationWrapper latestRevocationData = getLatestRevocationData();
		return latestRevocationData != null && latestRevocationData.isStatus() && latestRevocationData.getRevocationDate() != null;
	}

	public boolean isValidCertificate() {
		final boolean signatureValid = (certificate.getBasicSignature() != null) && certificate.getBasicSignature().isSignatureValid();
		RevocationWrapper latestRevocationData = getLatestRevocationData();
		final boolean revocationValid = (latestRevocationData != null) && latestRevocationData.isStatus();
		final boolean trusted = certificate.isTrusted();

		final boolean validity = signatureValid && (trusted ? true : revocationValid);
		return validity;
	}

	public String getSerialNumber() {
		BigInteger serialNumber = certificate.getSerialNumber();
		return serialNumber == null ? Utils.EMPTY_STRING : serialNumber.toString();
	}

	public String getCommonName() {
		String cn = certificate.getCommonName();
		return cn == null ? Utils.EMPTY_STRING : cn;
	}

	public String getCountryName() {
		String c = certificate.getCountryName();
		return c == null ? Utils.EMPTY_STRING : c;
	}

	public String getGivenName() {
		String givenName = certificate.getGivenName();
		return givenName == null ? Utils.EMPTY_STRING : givenName;
	}

	public String getOrganizationName() {
		String o = certificate.getOrganizationName();
		return o == null ? Utils.EMPTY_STRING : o;
	}

	public String getOrganizationalUnit() {
		String ou = certificate.getOrganizationalUnit();
		return ou == null ? Utils.EMPTY_STRING : ou;
	}

	public String getSurname() {
		String surname = certificate.getSurname();
		return surname == null ? Utils.EMPTY_STRING : surname;
	}

	public String getPseudo() {
		String pseudo = certificate.getPseudonym();
		return pseudo == null ? Utils.EMPTY_STRING : pseudo;
	}

	public boolean isCertificateRelatedTSLWellSigned() {
		List<XmlTrustedServiceProviderType> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (Utils.isCollectionNotEmpty(trustedServiceProviders)) {
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
		if (Utils.isCollectionNotEmpty(distinguishedNames)) {
			for (XmlDistinguishedName distinguishedName : distinguishedNames) {
				if (Utils.areStringsEqual(distinguishedName.getFormat(), format)) {
					return distinguishedName.getValue();
				}
			}
		}
		return Utils.EMPTY_STRING;
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

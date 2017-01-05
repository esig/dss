package eu.europa.esig.dss.validation.reports.wrapper;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDistinguishedName;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOID;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedList;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProvider;
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
	protected XmlBasicSignature getCurrentBasicSignature() {
		return certificate.getBasicSignature();
	}

	@Override
	protected List<XmlChainItem> getCurrentCertificateChain() {
		return certificate.getCertificateChain();
	}

	@Override
	protected XmlSigningCertificate getCurrentSigningCertificate() {
		return certificate.getSigningCertificate();
	}

	public boolean isTrusted() {
		return certificate.isTrusted();
	}

	public List<String> getKeyUsages() {
		List<String> keyUsageBits = certificate.getKeyUsageBits();
		if (Utils.isCollectionNotEmpty(keyUsageBits)) {
			return keyUsageBits;
		}
		return new ArrayList<String>();
	}

	public boolean isRevocationDataAvailable() {
		return Utils.isCollectionNotEmpty(certificate.getRevocations());
	}

	public Set<RevocationWrapper> getRevocationData() {
		if (isRevocationDataAvailable()) {
			List<XmlRevocation> revocation = certificate.getRevocations();
			Set<RevocationWrapper> result = new HashSet<RevocationWrapper>();
			for (XmlRevocation xmlRevocationType : revocation) {
				result.add(new RevocationWrapper(xmlRevocationType));
			}
			return result;
		}
		return Collections.emptySet();
	}

	public RevocationWrapper getLatestRevocationData() {
		RevocationWrapper latest = null;
		for (RevocationWrapper revoc : getRevocationData()) {
			if (latest == null || (latest.getProductionDate() != null && revoc != null && revoc.getProductionDate() != null
					&& revoc.getProductionDate().after(latest.getProductionDate()))) {
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
		List<XmlTrustedServiceProvider> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (Utils.isCollectionNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProvider xmlTrustedServiceProvider : trustedServiceProviders) {
				List<String> qualifiers = xmlTrustedServiceProvider.getQualifiers();
				if (Utils.isCollectionNotEmpty(qualifiers)) {
					result.addAll(qualifiers);
				}
			}
		}
		return new ArrayList<String>(result);
	}

	public Date getCertificateTSPServiceExpiredCertsRevocationInfo() {
		List<XmlTrustedServiceProvider> trustedServiceProviders = certificate.getTrustedServiceProvider();
		if (Utils.isCollectionNotEmpty(trustedServiceProviders)) {
			for (XmlTrustedServiceProvider trustedServiceProvider : trustedServiceProviders) {
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

	public List<XmlDigestAlgoAndValue> getDigestAlgoAndValues() {
		return certificate.getDigestAlgoAndValues();
	}

	public List<XmlTrustedList> getTrustedListInfo() {
		return certificate.getTrustedLists();
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
		List<XmlOID> certificatePolicyIds = certificate.getCertificatePolicyIds();
		if (Utils.isCollectionNotEmpty(certificatePolicyIds)) {
			return getOidValues(certificatePolicyIds);
		} else {
			return Collections.emptyList();
		}
	}

	public List<String> getQCStatementIds() {
		List<XmlOID> certificateQCStatementIds = certificate.getQCStatementIds();
		if (Utils.isCollectionNotEmpty(certificateQCStatementIds)) {
			return getOidValues(certificateQCStatementIds);
		} else {
			return Collections.emptyList();
		}
	}

	public List<String> getQCTypes() {
		List<XmlOID> certificateQCTypeIds = certificate.getQCTypes();
		if (Utils.isCollectionNotEmpty(certificateQCTypeIds)) {
			return getOidValues(certificateQCTypeIds);
		} else {
			return Collections.emptyList();
		}
	}

	private List<String> getOidValues(List<XmlOID> xmlOids) {
		List<String> result = new ArrayList<String>();
		for (XmlOID xmlOID : xmlOids) {
			result.add(xmlOID.getValue());
		}
		return result;
	}

}

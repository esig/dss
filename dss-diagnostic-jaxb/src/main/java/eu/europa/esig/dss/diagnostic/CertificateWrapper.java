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
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDistinguishedName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedServiceProvider;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.SemanticsIdentifier;

public class CertificateWrapper extends AbstractTokenProxy {

	private final XmlCertificate certificate;

	public CertificateWrapper(XmlCertificate certificate) {
		Objects.requireNonNull(certificate, "XMLCertificate cannot be null!");
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

	public boolean isSelfSigned() {
		return certificate.isSelfSigned();
	}

	public List<KeyUsageBit> getKeyUsages() {
		List<KeyUsageBit> keyUsageBits = certificate.getKeyUsageBits();
		if (keyUsageBits != null) {
			return keyUsageBits;
		}
		return Collections.emptyList();
	}

	public boolean isRevocationDataAvailable() {
		return certificate.getRevocations() != null && certificate.getRevocations().size() > 0;
	}
	
	public List<CertificateSourceType> getSources() {
		return certificate.getSources();
	}

	public List<CertificateRevocationWrapper> getCertificateRevocationData() {
		List<CertificateRevocationWrapper> certRevocationWrappers = new ArrayList<>();
		List<XmlCertificateRevocation> revocations = certificate.getRevocations();
		for (XmlCertificateRevocation xmlCertificateRevocation : revocations) {
			certRevocationWrappers.add(new CertificateRevocationWrapper(xmlCertificateRevocation));
		}
		return certRevocationWrappers;
	}
	
	/**
	 * Returns revocation data by its id
	 * 
	 * @param revocationId {@link String} representing id of a revocation data to extract
	 * @return {@link CertificateRevocationWrapper}
	 */
	public CertificateRevocationWrapper getRevocationDataById(String revocationId) {
		for (CertificateRevocationWrapper revocationData : getCertificateRevocationData()) {
			if (revocationId.equals(revocationData.getId())) {
				return revocationData;
			}
		}
		return null;
	}
	
	public boolean isIdPkixOcspNoCheck() {
		return certificate.isIdPkixOcspNoCheck() != null && certificate.isIdPkixOcspNoCheck();
	}

	public boolean isIdKpOCSPSigning() {
		List<XmlOID> extendedKeyUsages = certificate.getExtendedKeyUsages();
		if (extendedKeyUsages != null) {
			for (XmlOID xmlOID : extendedKeyUsages) {
				if (ExtendedKeyUsage.OCSP_SIGNING.getOid().equals(xmlOID.getValue())) {
					return true;
				}
			}
		}
		return false;
	}

	public Date getNotBefore() {
		return certificate.getNotBefore();
	}

	public Date getNotAfter() {
		return certificate.getNotAfter();
	}
	
	public String getEntityKey() {
		return certificate.getEntityKey();
	}

	public Date getCertificateTSPServiceExpiredCertsRevocationInfo() {
		List<XmlTrustedServiceProvider> trustedServiceProviders = certificate.getTrustedServiceProviders();
		if (trustedServiceProviders != null) {
			for (XmlTrustedServiceProvider trustedServiceProvider : trustedServiceProviders) {
				List<XmlTrustedService> trustedServices = trustedServiceProvider.getTrustedServices();
				for (XmlTrustedService xmlTrustedService : trustedServices) {
					if (xmlTrustedService.getExpiredCertsRevocationInfo() != null) {
						return xmlTrustedService.getExpiredCertsRevocationInfo(); // TODO improve
					}
				}
			}
		}
		return null;
	}

	public String getSerialNumber() {
		BigInteger serialNumber = certificate.getSerialNumber();
		return serialNumber == null ? "" : serialNumber.toString();
	}

	public String getSubjectSerialNumber() {
		return certificate.getSubjectSerialNumber();
	}

	public String getTitle() {
		return certificate.getTitle();
	}

	public String getCommonName() {
		return certificate.getCommonName();
	}

	public String getCountryName() {
		return certificate.getCountryName();
	}

	public String getGivenName() {
		return certificate.getGivenName();
	}

	public String getOrganizationIdentifier() {
		return certificate.getOrganizationIdentifier();
	}

	public String getOrganizationName() {
		return certificate.getOrganizationName();
	}

	public String getOrganizationalUnit() {
		return certificate.getOrganizationalUnit();
	}

	public String getEmail() {
		return certificate.getEmail();
	}

	public String getLocality() {
		return certificate.getLocality();
	}

	public String getState() {
		return certificate.getState();
	}

	public String getSurname() {
		return certificate.getSurname();
	}

	public String getPseudo() {
		return certificate.getPseudonym();
	}
	
	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return certificate.getDigestAlgoAndValue();
	}

	public boolean isTrustedListReached() {
		List<XmlTrustedServiceProvider> tsps = certificate.getTrustedServiceProviders();
		return tsps != null && tsps.size() > 0;
	}

	public List<XmlTrustedServiceProvider> getTrustServiceProviders() {
		return certificate.getTrustedServiceProviders();
	}

	public List<TrustedServiceWrapper> getTrustedServices() {
		List<TrustedServiceWrapper> result = new ArrayList<>();
		List<XmlTrustedServiceProvider> tsps = certificate.getTrustedServiceProviders();
		if (tsps != null) {
			for (XmlTrustedServiceProvider tsp : tsps) {
				List<String> tspNames = getValues(tsp.getTSPNames());
				List<String> tspTradeNames = getValues(tsp.getTSPTradeNames());
				List<XmlTrustedService> trustedServices = tsp.getTrustedServices();
				if (trustedServices != null) {
					for (XmlTrustedService trustedService : trustedServices) {
						TrustedServiceWrapper wrapper = new TrustedServiceWrapper();
						wrapper.setTrustedList(tsp.getTL());
						wrapper.setListOfTrustedLists(tsp.getLOTL());
						wrapper.setTspNames(tspNames);
						wrapper.setTspTradeNames(tspTradeNames);
						wrapper.setServiceDigitalIdentifier(new CertificateWrapper(trustedService.getServiceDigitalIdentifier()));
						wrapper.setServiceNames(getValues(trustedService.getServiceNames()));
						wrapper.setStatus(trustedService.getStatus());
						wrapper.setType(trustedService.getServiceType());
						wrapper.setStartDate(trustedService.getStartDate());
						wrapper.setEndDate(trustedService.getEndDate());
						wrapper.setCapturedQualifiers(new ArrayList<>(trustedService.getCapturedQualifiers()));
						wrapper.setAdditionalServiceInfos(new ArrayList<>(trustedService.getAdditionalServiceInfoUris()));
						result.add(wrapper);
					}
				}
			}
		}
		return result;
	}

	private List<String> getValues(List<XmlLangAndValue> langAndValues) {
		return langAndValues.stream().map(t -> t.getValue()).collect(Collectors.toList());
	}

	public String getCertificateDN() {
		return getFormat(certificate.getSubjectDistinguishedName(), "RFC2253");
	}

	public String getCertificateIssuerDN() {
		return getFormat(certificate.getIssuerDistinguishedName(), "RFC2253");
	}

	private String getFormat(List<XmlDistinguishedName> distinguishedNames, String format) {
		if (distinguishedNames != null) {
			for (XmlDistinguishedName distinguishedName : distinguishedNames) {
				if (distinguishedName.getFormat().equals(format)) {
					return distinguishedName.getValue();
				}
			}
		}
		return "";
	}

	public List<String> getAuthorityInformationAccessUrls() {
		return certificate.getAuthorityInformationAccessUrls();
	}

	public List<String> getCRLDistributionPoints() {
		return certificate.getCRLDistributionPoints();
	}

	public List<String> getOCSPAccessUrls() {
		return certificate.getOCSPAccessUrls();
	}

	public List<String> getCpsUrls() {
		List<String> result = new ArrayList<>();
		List<XmlCertificatePolicy> certificatePolicyIds = certificate.getCertificatePolicies();
		if (certificatePolicyIds != null) {
			for (XmlCertificatePolicy xmlCertificatePolicy : certificatePolicyIds) {
				String cpsUrl = xmlCertificatePolicy.getCpsUrl();
				if (cpsUrl != null) {
					result.add(cpsUrl);
				}
			}
		}
		return result;
	}

	public List<String> getPolicyIds() {
		List<XmlCertificatePolicy> certificatePolicyIds = certificate.getCertificatePolicies();
		return getOidValues(certificatePolicyIds);
	}

	public List<String> getQCStatementIds() {
		List<XmlOID> certificateQCStatementIds = certificate.getQCStatementIds();
		return getOidValues(certificateQCStatementIds);
	}

	public List<String> getQCTypes() {
		List<XmlOID> certificateQCTypeIds = certificate.getQCTypes();
		return getOidValues(certificateQCTypeIds);
	}

	private List<String> getOidValues(List<? extends XmlOID> xmlOids) {
		List<String> result = new ArrayList<>();
		if (xmlOids != null) {
			for (XmlOID xmlOID : xmlOids) {
				result.add(xmlOID.getValue());
			}
		}
		return result;
	}

	@Override
	public byte[] getBinaries() {
		return certificate.getBase64Encoded();
	}

	public List<XmlOID> getExtendedKeyUsages() {
		return certificate.getExtendedKeyUsages();
	}

	public PSD2InfoWrapper getPSD2Info() {
		if (certificate.getPSD2Info() != null) {
			return new PSD2InfoWrapper(certificate.getPSD2Info());
		}
		return null;
	}

	public QCLimitValueWrapper getQCLimitValue() {
		if (certificate.getQCLimitValue() !=null) {
			return new QCLimitValueWrapper(certificate.getQCLimitValue());
		}
		return null;
	}

	public List<String> getSubjectAlternativeNames() {
		return certificate.getSubjectAlternativeNames();
	}

	public SemanticsIdentifier getSemanticsIdentifier() {
		XmlOID xmlOID = certificate.getSemanticsIdentifier();
		if (xmlOID != null) {
			return SemanticsIdentifier.fromOid(xmlOID.getValue());
		}
		return null;
	}

	public String getReadableCertificateName() {
		if (certificate.getCommonName() != null) {
			return certificate.getCommonName();
		}
		if (certificate.getGivenName() != null) {
			return certificate.getGivenName();
		}
		if (certificate.getSurname() != null) {
			return certificate.getSurname();
		}
		if (certificate.getPseudonym() != null) {
			return certificate.getPseudonym();
		}
		if (certificate.getOrganizationName() != null) {
			return certificate.getOrganizationName();
		}
		if (certificate.getOrganizationalUnit() != null) {
			return certificate.getOrganizationalUnit();
		}
		return "?";
	}

}

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

import eu.europa.esig.dss.ExtendedKeyUsageOids;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlCertificatePolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlChainItem;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.jaxb.diagnostic.XmlDistinguishedName;
import eu.europa.esig.dss.jaxb.diagnostic.XmlOID;
import eu.europa.esig.dss.jaxb.diagnostic.XmlRevocation;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSigningCertificate;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
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

	public boolean isSelfSigned() {
		return certificate.isSelfSigned();
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
		List<XmlOID> extendedKeyUsages = certificate.getExtendedKeyUsages();
		if (Utils.isCollectionNotEmpty(extendedKeyUsages)) {
			for (XmlOID xmlOID : extendedKeyUsages) {
				if (Utils.areStringsEqual(ExtendedKeyUsageOids.OCSP_SIGNING.getOid(), xmlOID.getValue())) {
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

	public Date getCertificateTSPServiceExpiredCertsRevocationInfo() {
		List<XmlTrustedServiceProvider> trustedServiceProviders = certificate.getTrustedServiceProviders();
		if (Utils.isCollectionNotEmpty(trustedServiceProviders)) {
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
		return certificate.getCommonName();
	}

	public String getCountryName() {
		return certificate.getCountryName();
	}

	public String getGivenName() {
		return certificate.getGivenName();
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

	public List<XmlDigestAlgoAndValue> getDigestAlgoAndValues() {
		return certificate.getDigestAlgoAndValues();
	}

	public boolean hasTrustedServices() {
		List<XmlTrustedServiceProvider> tsps = certificate.getTrustedServiceProviders();
		return Utils.isCollectionNotEmpty(tsps);
	}

	public List<XmlTrustedServiceProvider> getTrustServiceProviders() {
		return certificate.getTrustedServiceProviders();
	}

	public List<TrustedServiceWrapper> getTrustedServices() {
		List<TrustedServiceWrapper> result = new ArrayList<TrustedServiceWrapper>();
		List<XmlTrustedServiceProvider> tsps = certificate.getTrustedServiceProviders();
		if (Utils.isCollectionNotEmpty(tsps)) {
			for (XmlTrustedServiceProvider tsp : tsps) {
				List<XmlTrustedService> trustedServices = tsp.getTrustedServices();
				if (Utils.isCollectionNotEmpty(trustedServices)) {
					for (XmlTrustedService trustedService : trustedServices) {
						TrustedServiceWrapper wrapper = new TrustedServiceWrapper();
						wrapper.setTspName(tsp.getTSPName());
						wrapper.setServiceName(trustedService.getServiceName());
						wrapper.setCountryCode(tsp.getCountryCode());
						wrapper.setStatus(trustedService.getStatus());
						wrapper.setType(trustedService.getServiceType());
						wrapper.setStartDate(trustedService.getStartDate());
						wrapper.setEndDate(trustedService.getEndDate());
						wrapper.setCapturedQualifiers(new ArrayList<String>(trustedService.getCapturedQualifiers()));
						wrapper.setAdditionalServiceInfos(new ArrayList<String>(trustedService.getAdditionalServiceInfoUris()));
						result.add(wrapper);
					}
				}
			}
		}
		return result;
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
		List<String> result = new ArrayList<String>();
		List<XmlCertificatePolicy> certificatePolicyIds = certificate.getCertificatePolicies();
		if (Utils.isCollectionNotEmpty(certificatePolicyIds)) {
			for (XmlCertificatePolicy xmlCertificatePolicy : certificatePolicyIds) {
				if (Utils.isStringNotBlank(xmlCertificatePolicy.getCpsUrl())) {
					result.add(xmlCertificatePolicy.getCpsUrl());
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
		List<String> result = new ArrayList<String>();
		if (Utils.isCollectionNotEmpty(xmlOids)) {
			for (XmlOID xmlOID : xmlOids) {
				result.add(xmlOID.getValue());
			}
		}
		return result;
	}

	public Set<String> getTrustedListCountryCodes() {
		Set<String> countryCodes = new HashSet<String>();
		List<XmlTrustedServiceProvider> trustedServiceProviders = certificate.getTrustedServiceProviders();
		for (XmlTrustedServiceProvider tsp : trustedServiceProviders) {
			countryCodes.add(tsp.getCountryCode());
		}
		return countryCodes;
	}

	public byte[] getBinaries() {
		return certificate.getBase64Encoded();
	}

	public List<XmlOID> getExtendedKeyUsages() {
		return certificate.getExtendedKeyUsages();
	}

}

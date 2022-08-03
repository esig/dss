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

import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlMRATrustServiceMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOriginalThirdCountryQcStatementsMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOriginalThirdCountryTrustedServiceMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedServiceProvider;
import eu.europa.esig.dss.enumerations.CertificateSourceType;
import eu.europa.esig.dss.enumerations.ExtendedKeyUsage;
import eu.europa.esig.dss.enumerations.KeyUsageBit;
import eu.europa.esig.dss.enumerations.QCType;
import eu.europa.esig.dss.enumerations.SemanticsIdentifier;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Provides a user-friendly interface of dealing with JAXB {@code XmlCertificate}
 *
 */
public class CertificateWrapper extends AbstractTokenProxy {

	/** The wrapped XmlCertificate instance */
	private final XmlCertificate certificate;

	/**
	 * Default constructor
	 *
	 * @param certificate {@link XmlCertificate} to be wrapped
	 */
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

	/**
	 * Returns if the certificate is trusted
	 *
	 * @return TRUE if the certificate is trusted, FALSE otherwise
	 */
	public boolean isTrusted() {
		return certificate.isTrusted();
	}

	/**
	 * Returns if the certificate is self-signed
	 *
	 * @return TRUE if the certificate is self-signed, FALSE otherwise
	 */
	public boolean isSelfSigned() {
		return certificate.isSelfSigned();
	}

	/**
	 * Returns the defined key-usages for the certificate
	 *
	 * @return a list of {@link KeyUsageBit}s
	 */
	public List<KeyUsageBit> getKeyUsages() {
		List<KeyUsageBit> keyUsageBits = certificate.getKeyUsageBits();
		if (keyUsageBits != null) {
			return keyUsageBits;
		}
		return Collections.emptyList();
	}

	/**
	 * Returns if the revocation data is available for the certificate
	 *
	 * @return TRUE if the revocation data is available, FALSE otherwise
	 */
	public boolean isRevocationDataAvailable() {
		return certificate.getRevocations() != null && !certificate.getRevocations().isEmpty();
	}

	/**
	 * Returns a list of sources the certificate has been obtained from (e.g. TRUSTED_LIST, SIGNATURE, AIA, etc.)
	 *
	 * @return a list of {@link CertificateSourceType}s
	 */
	public List<CertificateSourceType> getSources() {
		return certificate.getSources();
	}

	/**
	 * Returns a list of revocation data relevant to the certificate
	 *
	 * @return a list of {@link CertificateRevocationWrapper}s
	 */
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

	/**
	 * Returns if the certificate has id-pkix-ocsp-no-check attribute
	 *
	 * @return TRUE if the certificate has id-pkix-ocsp-no-check attribute, FALSE otherwise
	 */
	public boolean isIdPkixOcspNoCheck() {
		return certificate.isIdPkixOcspNoCheck() != null && certificate.isIdPkixOcspNoCheck();
	}

	/**
	 * Checks if the certificate has an extended-key-usage "ocspSigning" (1.3.6.1.5.5.7.3.9)
	 *
	 * @return TRUE if the certificate has extended-key-usage "ocspSigning", FALSE otherwise
	 */
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

	/**
	 * Returns the certificate's notBefore date (the date the certificate cannot be used before)
	 *
	 * @return {@link Date} notBefore
	 */
	public Date getNotBefore() {
		return certificate.getNotBefore();
	}

	/**
	 * Returns the certificate's notAfter date (the date the certificate cannot be used after)
	 *
	 * @return {@link Date} notAfter
	 */
	public Date getNotAfter() {
		return certificate.getNotAfter();
	}

	/**
	 * Returns a string identifier of the certificate's public key
	 *
	 * @return {@link String} public key's identifier
	 */
	public String getEntityKey() {
		return certificate.getEntityKey();
	}

	/**
	 * Returns expiredCertsRevocationInfo extension from TL Trusted Serviced
	 *
	 * @return {@link Date} expiredCertsRevocationInfo extension
	 */
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

	/**
	 * Returns the serial number of the certificate
	 *
	 * @return {@link String}
	 */
	public String getSerialNumber() {
		BigInteger serialNumber = certificate.getSerialNumber();
		return serialNumber == null ? "" : serialNumber.toString();
	}

	/**
	 * Returns the subject serial number of the certificate
	 *
	 * @return {@link String}
	 */
	public String getSubjectSerialNumber() {
		return certificate.getSubjectSerialNumber();
	}

	/**
	 * Returns the title
	 *
	 * @return {@link String}
	 */
	public String getTitle() {
		return certificate.getTitle();
	}

	/**
	 * Returns the common name
	 *
	 * @return {@link String}
	 */
	public String getCommonName() {
		return certificate.getCommonName();
	}

	/**
	 * Returns the country code
	 *
	 * @return {@link String}
	 */
	public String getCountryName() {
		return certificate.getCountryName();
	}

	/**
	 * Returns the given name
	 *
	 * @return {@link String}
	 */
	public String getGivenName() {
		return certificate.getGivenName();
	}

	/**
	 * Returns the organization identifier
	 *
	 * @return {@link String}
	 */
	public String getOrganizationIdentifier() {
		return certificate.getOrganizationIdentifier();
	}

	/**
	 * Returns the organization name
	 *
	 * @return {@link String}
	 */
	public String getOrganizationName() {
		return certificate.getOrganizationName();
	}

	/**
	 * Returns the organization unit
	 *
	 * @return {@link String}
	 */
	public String getOrganizationalUnit() {
		return certificate.getOrganizationalUnit();
	}

	/**
	 * Returns the email
	 *
	 * @return {@link String}
	 */
	public String getEmail() {
		return certificate.getEmail();
	}

	/**
	 * Returns the locality
	 *
	 * @return {@link String}
	 */
	public String getLocality() {
		return certificate.getLocality();
	}

	/**
	 * Returns the state
	 *
	 * @return {@link String}
	 */
	public String getState() {
		return certificate.getState();
	}

	/**
	 * Returns the surname
	 *
	 * @return {@link String}
	 */
	public String getSurname() {
		return certificate.getSurname();
	}

	/**
	 * Returns the pseudo
	 *
	 * @return {@link String}
	 */
	public String getPseudo() {
		return certificate.getPseudonym();
	}

	/**
	 * Returns the certificate's Digest if present
	 *
	 * @return {@link XmlDigestAlgoAndValue}
	 */
	public XmlDigestAlgoAndValue getDigestAlgoAndValue() {
		return certificate.getDigestAlgoAndValue();
	}

	/**
	 * Returns if the Trusted List has been reached for the particular certificate
	 *
	 * @return TRUE if the Trusted List has been reached, FALSE otherwise
	 */
	public boolean isTrustedListReached() {
		List<XmlTrustedServiceProvider> tsps = certificate.getTrustedServiceProviders();
		return tsps != null && !tsps.isEmpty();
	}

	/**
	 * Returns a list of {@code XmlTrustedServiceProvider}s
	 *
	 * @return a list of {@link XmlTrustedServiceProvider}s
	 */
	public List<XmlTrustedServiceProvider> getTrustServiceProviders() {
		return certificate.getTrustedServiceProviders();
	}

	/**
	 * Returns a list of {@code TrustedServiceWrapper}s
	 *
	 * @return a list of {@link TrustedServiceWrapper}s
	 */
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
						wrapper.setEnactedMRA(trustedService.isEnactedMRA());

						XmlMRATrustServiceMapping mraTrustServiceMapping = trustedService.getMRATrustServiceMapping();
						if (mraTrustServiceMapping != null) {
							wrapper.setMraTrustServiceLegalIdentifier(mraTrustServiceMapping.getTrustServiceLegalIdentifier());
							wrapper.setMraTrustServiceEquivalenceStatusStartingTime(mraTrustServiceMapping.getEquivalenceStatusStartingTime());
							XmlOriginalThirdCountryTrustedServiceMapping originalThirdCountryMapping = mraTrustServiceMapping.getOriginalThirdCountryMapping();
							if (originalThirdCountryMapping != null) {
								wrapper.setOriginalTCType(originalThirdCountryMapping.getServiceType());
								wrapper.setOriginalTCStatus(originalThirdCountryMapping.getStatus());
								wrapper.setOriginalCapturedQualifiers(originalThirdCountryMapping.getCapturedQualifiers());
								wrapper.setOriginalTCAdditionalServiceInfos(originalThirdCountryMapping.getAdditionalServiceInfoUris());
							}
						}

						result.add(wrapper);
					}
				}
			}
		}
		return result;
	}

	private List<String> getValues(List<XmlLangAndValue> langAndValues) {
		return langAndValues.stream().map(XmlLangAndValue::getValue).collect(Collectors.toList());
	}

	/**
	 * Returns the certificate's Distinguished Name (by RFC 2253)
	 *
	 * @return {@link String}
	 */
	public String getCertificateDN() {
		DistinguishedNameListWrapper distinguishedNameListWrapper = new DistinguishedNameListWrapper(
				certificate.getSubjectDistinguishedName());
		return distinguishedNameListWrapper.getValue("RFC2253");
	}

	/**
	 * Returns the certificate issuer's Distinguished Name (by RFC 2253)
	 *
	 * @return {@link String}
	 */
	public String getCertificateIssuerDN() {
		DistinguishedNameListWrapper distinguishedNameListWrapper = new DistinguishedNameListWrapper(
				certificate.getIssuerDistinguishedName());
		return distinguishedNameListWrapper.getValue("RFC2253");
	}

	/**
	 * Returns the Authority Information Access URLs
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getAuthorityInformationAccessUrls() {
		return certificate.getAuthorityInformationAccessUrls();
	}

	/**
	 * Returns the CRL Distribution Points URLs
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getCRLDistributionPoints() {
		return certificate.getCRLDistributionPoints();
	}

	/**
	 * Returns the OCSP Access URLs
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getOCSPAccessUrls() {
		return certificate.getOCSPAccessUrls();
	}

	/**
	 * Returns the certificate policies URLs
	 *
	 * @return a list of {@link String}s
	 */
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

	/**
	 * Returns the certificate policies Ids
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getPolicyIds() {
		List<XmlCertificatePolicy> certificatePolicyIds = certificate.getCertificatePolicies();
		return getOidValues(certificatePolicyIds);
	}

	/**
	 * Returns if the certificate is QC compliant (has id-etsi-qcs-QcCompliance extension)
	 *
	 * @return TRUE if the certificate is QC compliant, FALSE otherwise
	 */
	public boolean isQcCompliance() {
		return certificate.getQcStatements() != null && certificate.getQcStatements().getQcCompliance() != null
				&& certificate.getQcStatements().getQcCompliance().isPresent();
	}

	/**
	 * Returns if the certificate is supported by QSCD (has id-etsi-qcs-QcSSCD extension)
	 *
	 * @return TRUE if the certificate is supported by QSCD, FALSE otherwise
	 */
	public boolean isSupportedByQSCD() {
		return certificate.getQcStatements() != null && certificate.getQcStatements().getQcSSCD() != null
				&& certificate.getQcStatements().getQcSSCD().isPresent();
	}

	/**
	 * Returns a list of QCTypes (present inside id-etsi-qcs-QcType extension)
	 *
	 * @return a list of {@link QCType}s
	 */
	public List<QCType> getQcTypes() {
		List<QCType> result = new ArrayList<>();
		if (certificate.getQcStatements() != null && certificate.getQcStatements().getQcTypes() != null) {
			for (XmlOID oid : certificate.getQcStatements().getQcTypes()) {
				result.add(QCType.fromOid(oid.getValue()));
			}
		}
		return result;
	}

	/**
	 * Returns a list of QCLegislation Country Codes (present inside id-etsi-qcs-QcCClegislation extension)
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getQcLegislationCountryCodes() {
		if (certificate.getQcStatements() != null && certificate.getQcStatements().getQcCClegislation() != null) {
			return certificate.getQcStatements().getQcCClegislation();
		}
		return Collections.emptyList();
	}

	/**
	 * Returns a list of QcStatements OIDs not supported by the implementation
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getOtherQcStatements() {
		if (certificate.getQcStatements() != null && certificate.getQcStatements().getOtherOIDs() != null) {
			return getOidValues(certificate.getQcStatements().getOtherOIDs());
		}
		return Collections.emptyList();
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

	/**
	 * This method returns a name of a Trusted Service used to apply translation for the certificate QcStatements
	 * based on the defined Mutual Recognition Agreement scheme
	 *
	 * @return {@link String}
	 */
	public String getMRAEnactedTrustServiceLegalIdentifier() {
		if (certificate.getQcStatements() != null && certificate.getQcStatements().getMRACertificateMapping() != null) {
			return certificate.getQcStatements().getMRACertificateMapping().getEnactedTrustServiceLegalIdentifier();
		}
		return null;
	}

	private XmlOriginalThirdCountryQcStatementsMapping getOriginalThirdCountryMapping() {
		if (certificate.getQcStatements() != null && certificate.getQcStatements().getMRACertificateMapping() != null) {
			return certificate.getQcStatements().getMRACertificateMapping().getOriginalThirdCountryMapping();
		}
		return null;
	}

	/**
	 * Returns if the certificate has been defined as QC compliant in a third-country Trusted List before MRA mapping
	 *
	 * @return TRUE if the certificate is QC compliant, FALSE otherwise
	 */
	public boolean isOriginalThirdCountryQcCompliance() {
		XmlOriginalThirdCountryQcStatementsMapping originalThirdCountryMapping = getOriginalThirdCountryMapping();
		return originalThirdCountryMapping != null && originalThirdCountryMapping.getQcCompliance() != null
				&& originalThirdCountryMapping.getQcCompliance().isPresent();
	}

	/**
	 * Returns if the certificate has been defined as supported by QSCD in a third-country Trusted List before MRA mapping
	 *
	 * @return TRUE if the certificate is supported by QSCD, FALSE otherwise
	 */
	public boolean isOriginalThirdCountrySupportedByQSCD() {
		XmlOriginalThirdCountryQcStatementsMapping originalThirdCountryMapping = getOriginalThirdCountryMapping();
		return originalThirdCountryMapping != null && originalThirdCountryMapping.getQcSSCD() != null
				&& originalThirdCountryMapping.getQcSSCD().isPresent();
	}

	/**
	 * Returns a list of QCTypes defined in a third-country Trusted List before MRA mapping
	 *
	 * @return a list of {@link QCType}s
	 */
	public List<QCType> getOriginalThirdCountryQCTypes() {
		List<QCType> result = new ArrayList<>();
		XmlOriginalThirdCountryQcStatementsMapping originalThirdCountryMapping = getOriginalThirdCountryMapping();
		if (originalThirdCountryMapping != null && originalThirdCountryMapping.getQcTypes() != null) {
			for (XmlOID oid : originalThirdCountryMapping.getQcTypes()) {
				result.add(QCType.fromOid(oid.getValue()));
			}
		}
		return result;
	}

	/**
	 * Returns a list of QCLegislation Country Codes defined in a third-country Trusted List before MRA mapping
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getOriginalThirdCountryQcLegislationCountryCodes() {
		XmlOriginalThirdCountryQcStatementsMapping originalThirdCountryMapping = getOriginalThirdCountryMapping();
		if (originalThirdCountryMapping != null && originalThirdCountryMapping.getQcCClegislation() != null) {
			return originalThirdCountryMapping.getQcCClegislation();
		}
		return Collections.emptyList();
	}

	/**
	 * Returns a list of QcStatements OIDs not supported by the implementation
	 * defined in a third-country Trusted List before MRA mapping
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getOriginalThirdCountryOtherQcStatements() {
		XmlOriginalThirdCountryQcStatementsMapping originalThirdCountryMapping = getOriginalThirdCountryMapping();
		if (originalThirdCountryMapping != null && originalThirdCountryMapping.getOtherOIDs() != null) {
			return getOidValues(originalThirdCountryMapping.getOtherOIDs());
		}
		return Collections.emptyList();
	}

	@Override
	public byte[] getBinaries() {
		return certificate.getBase64Encoded();
	}

	/**
	 * Returns a list of extended-key-usages
	 *
	 * @return a list of {@link XmlOID}s
	 */
	public List<XmlOID> getExtendedKeyUsages() {
		return certificate.getExtendedKeyUsages();
	}

	/**
	 * Returns the PSD2 QCStatement (id-etsi-psd2-qcStatement extension, ETSI TS 119 495)
	 *
	 * @return {@link PSD2InfoWrapper}
	 */
	public PSD2InfoWrapper getPSD2Info() {
		if (certificate.getQcStatements() !=null && certificate.getQcStatements().getPSD2QcInfo() != null) {
			return new PSD2InfoWrapper(certificate.getQcStatements().getPSD2QcInfo());
		}
		return null;
	}

	/**
	 * Returns the QCEuLimitValue
	 *
	 * @return {@link QCLimitValueWrapper}
	 */
	public QCLimitValueWrapper getQCLimitValue() {
		if (certificate.getQcStatements() !=null && certificate.getQcStatements().getQcEuLimitValue() !=null) {
			return new QCLimitValueWrapper(certificate.getQcStatements().getQcEuLimitValue());
		}
		return null;
	}

	/**
	 * Returns QcEuRetentionPeriod
	 *
	 * @return {@link Integer} retention period
	 */
	public Integer getQCEuRetentionPeriod() {
		if (certificate.getQcStatements() !=null ) {
			return certificate.getQcStatements().getQcEuRetentionPeriod();
		}
		return null;
	}

	/**
	 * Returns QcEuPDS Locations
	 *
	 * @return a list of {@link XmlLangAndValue}s
	 */
	public List<XmlLangAndValue> getQCPDSLocations() {
		if (certificate.getQcStatements() !=null) {
			return certificate.getQcStatements().getQcEuPDS();
		}
		return Collections.emptyList();
	}

	/**
	 * Returns the semantics identifier
	 *
	 * @return {@link SemanticsIdentifier}
	 */
	public SemanticsIdentifier getSemanticsIdentifier() {
		if (certificate.getQcStatements() != null && certificate.getQcStatements().getSemanticsIdentifier() != null) {
			XmlOID xmlOID = certificate.getQcStatements().getSemanticsIdentifier();
			if (xmlOID != null) {
				return SemanticsIdentifier.fromOid(xmlOID.getValue());
			}
		}
		return null;
	}

	/**
	 * Returns if the certificate contains id-etsi-ext-valassured-ST-certs extension,
	 * as defined in ETSI EN 319 412-1 "5.2 Certificate Extensions regarding Validity Assured Certificate"
	 *
	 * @return TRUE if the certificate is a validity assured short-term certificate, FALSE otherwise
	 */
	public boolean isValAssuredShortTermCertificate() {
		return certificate.isValAssuredShortTermCertificate() != null && certificate.isValAssuredShortTermCertificate();
	}

	/**
	 * Returns subject alternative names
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getSubjectAlternativeNames() {
		return certificate.getSubjectAlternativeNames();
	}

	/**
	 * Returns human-readable certificate name
	 *
	 * @return {@link String}
	 */
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

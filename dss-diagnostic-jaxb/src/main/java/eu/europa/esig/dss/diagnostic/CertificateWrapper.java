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

import eu.europa.esig.dss.diagnostic.jaxb.XmlAuthorityInformationAccess;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicConstraints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlBasicSignature;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCRLDistributionPoints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateContentEquivalence;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateExtension;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicies;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificatePolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlCertificateRevocation;
import eu.europa.esig.dss.diagnostic.jaxb.XmlChainItem;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestAlgoAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlExtendedKeyUsages;
import eu.europa.esig.dss.diagnostic.jaxb.XmlGeneralName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlGeneralSubtree;
import eu.europa.esig.dss.diagnostic.jaxb.XmlIdPkixOcspNoCheck;
import eu.europa.esig.dss.diagnostic.jaxb.XmlInhibitAnyPolicy;
import eu.europa.esig.dss.diagnostic.jaxb.XmlKeyUsages;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlMRATrustServiceMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlNameConstraints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOriginalThirdCountryQcStatementsMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOriginalThirdCountryTrustedServiceMapping;
import eu.europa.esig.dss.diagnostic.jaxb.XmlPolicyConstraints;
import eu.europa.esig.dss.diagnostic.jaxb.XmlQcStatements;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSigningCertificate;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSubjectAlternativeNames;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSubjectKeyIdentifier;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedServiceProvider;
import eu.europa.esig.dss.diagnostic.jaxb.XmlValAssuredShortTermCertificate;
import eu.europa.esig.dss.enumerations.CertificateExtensionEnum;
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
	 * Returns a list of all certificate extensions
	 *
	 * @return a list of {@link XmlCertificateExtension}
	 */
	public List<XmlCertificateExtension> getCertificateExtensions() {
		return new ArrayList<>(certificate.getCertificateExtensions());
	}

	/**
	 * Returns a certificate extension with the given {@code oid} when present
	 *
	 * @param oid {@link String} OID of the certificate extension
	 * @return {@link XmlCertificateExtension} when present, NULL otherwise
	 */
	public <T extends XmlCertificateExtension> T getCertificateExtensionForOid(String oid, Class<T> targetClass) {
		for (XmlCertificateExtension certificateExtension : getCertificateExtensions()) {
			if (oid.equals(certificateExtension.getOID())) {
				if (targetClass.isInstance(certificateExtension)) {
					return (T) certificateExtension;
				} else {
					throw new UnsupportedOperationException(String.format("A certificate extension with " +
							"OID '%s' shall be in instance of '%s' class!", oid, targetClass.getName()));
				}
			}
		}
		return null;
	}

	/**
	 * Returns subject alternative names
	 *
	 * @return a list of {@link String}s
	 */
	public List<XmlGeneralName> getSubjectAlternativeNames() {
		XmlSubjectAlternativeNames subjectAlternativeNames = getXmlSubjectAlternativeNames();
		return subjectAlternativeNames != null ? subjectAlternativeNames.getSubjectAlternativeName() : Collections.emptyList();
	}

	private XmlSubjectAlternativeNames getXmlSubjectAlternativeNames() {
		return getCertificateExtensionForOid(CertificateExtensionEnum.SUBJECT_ALTERNATIVE_NAME.getOid(), XmlSubjectAlternativeNames.class);
	}

	/**
	 * Returns whether the certificate defines BasicConstraints.cA extension set to TRUE
	 *
	 * @return TRUE if the BasicConstraints.cA extension is defined and set to true, FALSE otherwise
	 */
	public boolean isCA() {
		XmlBasicConstraints basicConstraints = getXmlBasicConstraints();
		return basicConstraints != null && basicConstraints.isCA();
	}

	/**
	 * Returns value of BasicConstraints.PathLenConstraint if present and BasicConstraints.cA is set to true
	 *
	 * @return integer value of BasicConstraints.PathLenConstraint if applicable, -1 otherwise
	 */
	public int getPathLenConstraint() {
		XmlBasicConstraints basicConstraints = getXmlBasicConstraints();
		return basicConstraints != null && basicConstraints.isCA() && basicConstraints.getPathLenConstraint() != null
				? basicConstraints.getPathLenConstraint() : -1;
	}

	private XmlBasicConstraints getXmlBasicConstraints() {
		return getCertificateExtensionForOid(CertificateExtensionEnum.BASIC_CONSTRAINTS.getOid(), XmlBasicConstraints.class);
	}

	/**
	 * Returns value of the requireExplicitPolicy field of policyConstraints certificate extension
	 *
	 * @return requireExplicitPolicy value if present, -1 otherwise
	 */
	public int getRequireExplicitPolicy() {
		XmlPolicyConstraints policyConstraints = getXmlPolicyConstraints();
		return policyConstraints != null && policyConstraints.getRequireExplicitPolicy() != null ?
				policyConstraints.getRequireExplicitPolicy() : -1;
	}

	/**
	 * Returns value of the inhibitPolicyMapping field of policyConstraints certificate extension
	 *
	 * @return inhibitPolicyMapping value if present, -1 otherwise
	 */
	public int getInhibitPolicyMapping() {
		XmlPolicyConstraints policyConstraints = getXmlPolicyConstraints();
		return policyConstraints != null && policyConstraints.getInhibitPolicyMapping() != null ?
				policyConstraints.getInhibitPolicyMapping() : -1;
	}

	private XmlPolicyConstraints getXmlPolicyConstraints() {
		return getCertificateExtensionForOid(CertificateExtensionEnum.POLICY_CONSTRAINTS.getOid(), XmlPolicyConstraints.class);
	}

	/**
	 * Returns value of the inhibitAnyPolicy certificate extension's value
	 *
	 * @return inhibitAnyPolicy certificate extension's value if present, -1 otherwise
	 */
	public int getInhibitAnyPolicy() {
		XmlInhibitAnyPolicy inhibitAnyPolicy = getXmlInhibitAnyPolicy();
		return inhibitAnyPolicy != null && inhibitAnyPolicy.getValue() != null ?
				inhibitAnyPolicy.getValue() : -1;
	}

	private XmlInhibitAnyPolicy getXmlInhibitAnyPolicy() {
		return getCertificateExtensionForOid(CertificateExtensionEnum.INHIBIT_ANY_POLICY.getOid(), XmlInhibitAnyPolicy.class);
	}

	/**
	 * Returns value of the permittedSubtrees field of nameConstraints certificate extension, when present
	 *
	 * @return list of {@link XmlGeneralSubtree} if field is present, empty list otherwise
	 */
	public List<XmlGeneralSubtree> getPermittedSubtrees() {
		XmlNameConstraints nameConstraints = getXmlNameConstraints();
		return nameConstraints != null ? nameConstraints.getPermittedSubtrees() : Collections.emptyList();
	}

	/**
	 * Returns value of the excludedSubtrees field of nameConstraints certificate extension, when present
	 *
	 * @return list of {@link XmlGeneralSubtree} if field is present, empty list otherwise
	 */
	public List<XmlGeneralSubtree> getExcludedSubtrees() {
		XmlNameConstraints nameConstraints = getXmlNameConstraints();
		return nameConstraints != null ? nameConstraints.getExcludedSubtrees() : Collections.emptyList();
	}

	private XmlNameConstraints getXmlNameConstraints() {
		return getCertificateExtensionForOid(CertificateExtensionEnum.NAME_CONSTRAINTS.getOid(), XmlNameConstraints.class);
	}

	/**
	 * Returns the defined key-usages for the certificate
	 *
	 * @return a list of {@link KeyUsageBit}s
	 */
	public List<KeyUsageBit> getKeyUsages() {
		XmlKeyUsages keyUsage = getXmlKeyUsage();
		return keyUsage != null ? keyUsage.getKeyUsageBit() : Collections.emptyList();
	}

	private XmlKeyUsages getXmlKeyUsage() {
		return getCertificateExtensionForOid(CertificateExtensionEnum.KEY_USAGE.getOid(), XmlKeyUsages.class);
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
		XmlIdPkixOcspNoCheck ocspNoCheck = getXmlIdPkixOcspNoCheck();
		return ocspNoCheck != null && ocspNoCheck.isPresent();
	}

	private XmlIdPkixOcspNoCheck getXmlIdPkixOcspNoCheck() {
		return getCertificateExtensionForOid(CertificateExtensionEnum.OCSP_NOCHECK.getOid(), XmlIdPkixOcspNoCheck.class);
	}

	/**
	 * Checks if the certificate has an extended-key-usage "ocspSigning" (1.3.6.1.5.5.7.3.9)
	 *
	 * @return TRUE if the certificate has extended-key-usage "ocspSigning", FALSE otherwise
	 */
	public boolean isIdKpOCSPSigning() {
		XmlExtendedKeyUsages extendedKeyUsage = getXmlExtendedKeyUsages();
		if (extendedKeyUsage != null) {
			for (XmlOID xmlOID : extendedKeyUsage.getExtendedKeyUsageOid()) {
				if (ExtendedKeyUsage.OCSP_SIGNING.getOid().equals(xmlOID.getValue())) {
					return true;
				}
			}
		}
		return false;
	}
	/**
	 * Returns if the certificate contains id-etsi-ext-valassured-ST-certs extension,
	 * as defined in ETSI EN 319 412-1 "5.2 Certificate Extensions regarding Validity Assured Certificate"
	 *
	 * @return TRUE if the certificate is a validity assured short-term certificate, FALSE otherwise
	 */
	public boolean isValAssuredShortTermCertificate() {
		XmlValAssuredShortTermCertificate valAssuredShortTermCertificate = getXmlValAssuredShortTermCertificate();
		return valAssuredShortTermCertificate != null && valAssuredShortTermCertificate.isPresent();
	}

	private XmlValAssuredShortTermCertificate getXmlValAssuredShortTermCertificate() {
		return getCertificateExtensionForOid(CertificateExtensionEnum.VALIDITY_ASSURED_SHORT_TERM.getOid(), XmlValAssuredShortTermCertificate.class);
	}

	/**
	 * Returns a list of extended-key-usages
	 *
	 * @return a list of {@link XmlOID}s
	 */
	public List<XmlOID> getExtendedKeyUsages() {
		XmlExtendedKeyUsages extendedKeyUsage = getXmlExtendedKeyUsages();
		return extendedKeyUsage != null ? extendedKeyUsage.getExtendedKeyUsageOid() : Collections.emptyList();
	}

	private XmlExtendedKeyUsages getXmlExtendedKeyUsages() {
		return getCertificateExtensionForOid(CertificateExtensionEnum.EXTENDED_KEY_USAGE.getOid(), XmlExtendedKeyUsages.class);
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
							wrapper.setMraTrustServiceEquivalenceStatusEndingTime(mraTrustServiceMapping.getEquivalenceStatusEndingTime());
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
	 * Returns the CRL Distribution Points URLs
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getCRLDistributionPoints() {
		XmlCRLDistributionPoints crlDistributionPoints = getXmlCRLDistributionPoints();
		if (crlDistributionPoints != null) {
			return crlDistributionPoints.getCrlUrl();
		}
		return Collections.emptyList();
	}

	private XmlCRLDistributionPoints getXmlCRLDistributionPoints() {
		return getCertificateExtensionForOid(CertificateExtensionEnum.CRL_DISTRIBUTION_POINTS.getOid(), XmlCRLDistributionPoints.class);
	}

	/**
	 * Returns the Authority Information Access URLs
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getCAIssuersAccessUrls() {
		XmlAuthorityInformationAccess authorityInformationAccess = getXmlAuthorityInformationAccess();
		if (authorityInformationAccess != null) {
			return authorityInformationAccess.getCaIssuersUrls();
		}
		return Collections.emptyList();
	}

	/**
	 * Returns the OCSP Access URLs
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getOCSPAccessUrls() {
		XmlAuthorityInformationAccess authorityInformationAccess = getXmlAuthorityInformationAccess();
		if (authorityInformationAccess != null) {
			return authorityInformationAccess.getOcspUrls();
		}
		return Collections.emptyList();
	}

	private XmlAuthorityInformationAccess getXmlAuthorityInformationAccess() {
		return getCertificateExtensionForOid(CertificateExtensionEnum.AUTHORITY_INFORMATION_ACCESS.getOid(), XmlAuthorityInformationAccess.class);
	}

	/**
	 * Returns the Subject Key Identifier certificate extension's value, when present
	 *
	 * @return byte array representing the Subject Key Identifier
	 */
	public byte[] getSubjectKeyIdentifier() {
		XmlSubjectKeyIdentifier xmlSubjectKeyIdentifier = getXmlSubjectKeyIdentifier();
		if (xmlSubjectKeyIdentifier != null) {
			return xmlSubjectKeyIdentifier.getSki();
		}
		return null;
	}

	private XmlSubjectKeyIdentifier getXmlSubjectKeyIdentifier() {
		return getCertificateExtensionForOid(CertificateExtensionEnum.SUBJECT_KEY_IDENTIFIER.getOid(), XmlSubjectKeyIdentifier.class);
	}

	/**
	 * Returns the certificate policies URLs
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getCpsUrls() {
		List<String> result = new ArrayList<>();
		XmlCertificatePolicies xmlCertificatePolicies = getXmlCertificatePolicies();
		if (xmlCertificatePolicies != null) {
			for (XmlCertificatePolicy xmlCertificatePolicy : xmlCertificatePolicies.getCertificatePolicy()) {
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
		XmlCertificatePolicies xmlCertificatePolicies = getXmlCertificatePolicies();
		if (xmlCertificatePolicies != null) {
			List<XmlCertificatePolicy> certificatePolicyIds = xmlCertificatePolicies.getCertificatePolicy();
			return getOidValues(certificatePolicyIds);
		}
		return Collections.emptyList();
	}

	/**
	 * Returns the certificate policies Ids
	 *
	 * @return a list of {@link String}s
	 */
	public List<XmlCertificatePolicy> getCertificatePolicies() {
		XmlCertificatePolicies xmlCertificatePolicies = getXmlCertificatePolicies();
		if (xmlCertificatePolicies != null) {
			return xmlCertificatePolicies.getCertificatePolicy();
		}
		return Collections.emptyList();
	}

	private XmlCertificatePolicies getXmlCertificatePolicies() {
		return getCertificateExtensionForOid(CertificateExtensionEnum.CERTIFICATE_POLICIES.getOid(), XmlCertificatePolicies.class);
	}

	/**
	 * Returns if the certificate is QC compliant (has id-etsi-qcs-QcCompliance extension)
	 *
	 * @return TRUE if the certificate is QC compliant, FALSE otherwise
	 */
	public boolean isQcCompliance() {
		XmlQcStatements xmlQcStatements = getXmlQcStatements();
		return xmlQcStatements != null && xmlQcStatements.getQcCompliance() != null
				&& xmlQcStatements.getQcCompliance().isPresent();
	}

	/**
	 * Returns if the certificate is supported by QSCD (has id-etsi-qcs-QcSSCD extension)
	 *
	 * @return TRUE if the certificate is supported by QSCD, FALSE otherwise
	 */
	public boolean isSupportedByQSCD() {
		XmlQcStatements xmlQcStatements = getXmlQcStatements();
		return xmlQcStatements != null && xmlQcStatements.getQcSSCD() != null
				&& xmlQcStatements.getQcSSCD().isPresent();
	}

	/**
	 * Returns a list of QCTypes (present inside id-etsi-qcs-QcType extension)
	 *
	 * @return a list of {@link QCType}s
	 */
	public List<QCType> getQcTypes() {
		List<QCType> result = new ArrayList<>();
		XmlQcStatements xmlQcStatements = getXmlQcStatements();
		if (xmlQcStatements != null && xmlQcStatements.getQcTypes() != null) {
			for (XmlOID oid : xmlQcStatements.getQcTypes()) {
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
		XmlQcStatements xmlQcStatements = getXmlQcStatements();
		if (xmlQcStatements != null && xmlQcStatements.getQcCClegislation() != null) {
			return xmlQcStatements.getQcCClegislation();
		}
		return Collections.emptyList();
	}

	/**
	 * Returns the PSD2 QCStatement (id-etsi-psd2-qcStatement extension, ETSI TS 119 495)
	 *
	 * @return {@link PSD2InfoWrapper}
	 */
	public PSD2InfoWrapper getPSD2Info() {
		XmlQcStatements xmlQcStatements = getXmlQcStatements();
		if (xmlQcStatements != null && xmlQcStatements.getPSD2QcInfo() != null) {
			return new PSD2InfoWrapper(xmlQcStatements.getPSD2QcInfo());
		}
		return null;
	}

	/**
	 * Returns the QCEuLimitValue
	 *
	 * @return {@link QCLimitValueWrapper}
	 */
	public QCLimitValueWrapper getQCLimitValue() {
		XmlQcStatements xmlQcStatements = getXmlQcStatements();
		if (xmlQcStatements != null && xmlQcStatements.getQcEuLimitValue() !=null) {
			return new QCLimitValueWrapper(xmlQcStatements.getQcEuLimitValue());
		}
		return null;
	}

	/**
	 * Returns QcEuRetentionPeriod
	 *
	 * @return {@link Integer} retention period
	 */
	public Integer getQCEuRetentionPeriod() {
		XmlQcStatements xmlQcStatements = getXmlQcStatements();
		if (xmlQcStatements != null ) {
			return xmlQcStatements.getQcEuRetentionPeriod();
		}
		return null;
	}

	/**
	 * Returns QcEuPDS Locations
	 *
	 * @return a list of {@link XmlLangAndValue}s
	 */
	public List<XmlLangAndValue> getQCPDSLocations() {
		XmlQcStatements xmlQcStatements = getXmlQcStatements();
		if (xmlQcStatements != null) {
			return xmlQcStatements.getQcEuPDS();
		}
		return Collections.emptyList();
	}

	/**
	 * Returns the semantics identifier
	 *
	 * @return {@link SemanticsIdentifier}
	 */
	public SemanticsIdentifier getSemanticsIdentifier() {
		XmlQcStatements xmlQcStatements = getXmlQcStatements();
		if (xmlQcStatements != null && xmlQcStatements.getSemanticsIdentifier() != null) {
			XmlOID xmlOID = xmlQcStatements.getSemanticsIdentifier();
			if (xmlOID != null) {
				return SemanticsIdentifier.fromOid(xmlOID.getValue());
			}
		}
		return null;
	}

	/**
	 * Returns a list of QcStatements OIDs not supported by the implementation
	 *
	 * @return a list of {@link String}s
	 */
	public List<String> getOtherQcStatements() {
		XmlQcStatements xmlQcStatements = getXmlQcStatements();
		if (xmlQcStatements != null && xmlQcStatements.getOtherOIDs() != null) {
			return getOidValues(xmlQcStatements.getOtherOIDs());
		}
		return Collections.emptyList();
	}

	/**
	 * Returns if the MRA has been enacted
	 *
	 * @return TRUE if the MRA has been enacted, FALSE otherwise
	 */
	public boolean isEnactedMRA() {
		XmlQcStatements xmlQcStatements = getXmlQcStatements();
		if (xmlQcStatements != null) {
			return xmlQcStatements.isEnactedMRA() != null && xmlQcStatements.isEnactedMRA();
		}
		return false;
	}

	/**
	 * This method returns a name of a Trusted Service used to apply translation for the certificate QcStatements
	 * based on the defined Mutual Recognition Agreement scheme
	 *
	 * @return {@link String}
	 */
	public String getMRAEnactedTrustServiceLegalIdentifier() {
		XmlQcStatements xmlQcStatements = getXmlQcStatements();
		if (xmlQcStatements != null && xmlQcStatements.getMRACertificateMapping() != null &&
				xmlQcStatements.getMRACertificateMapping().getTrustServiceEquivalenceInformation() != null) {
			return xmlQcStatements.getMRACertificateMapping().getTrustServiceEquivalenceInformation().getTrustServiceLegalIdentifier();
		}
		return null;
	}

	/**
	 * Returns a {@code XmlCertificateContentEquivalence} list corresponding to the matching MRA information
	 *
	 * @return a list of {@link XmlCertificateContentEquivalence}s
	 */
	public List<XmlCertificateContentEquivalence> getMRACertificateContentEquivalenceList() {
		XmlQcStatements xmlQcStatements = getXmlQcStatements();
		if (xmlQcStatements != null && xmlQcStatements.getMRACertificateMapping() != null &&
				xmlQcStatements.getMRACertificateMapping().getTrustServiceEquivalenceInformation() != null) {
			return xmlQcStatements.getMRACertificateMapping().getTrustServiceEquivalenceInformation().getCertificateContentEquivalenceList();
		}
		return Collections.emptyList();
	}

	private XmlOriginalThirdCountryQcStatementsMapping getOriginalThirdCountryMapping() {
		XmlQcStatements xmlQcStatements = getXmlQcStatements();
		if (xmlQcStatements != null && xmlQcStatements.getMRACertificateMapping() != null) {
			return xmlQcStatements.getMRACertificateMapping().getOriginalThirdCountryMapping();
		}
		return null;
	}

	private XmlQcStatements getXmlQcStatements() {
		return getCertificateExtensionForOid(CertificateExtensionEnum.QC_STATEMENTS.getOid(), XmlQcStatements.class);
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

	public int hashCode() {
		return super.hashCode();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (!(obj instanceof CertificateWrapper))
			return false;
		AbstractTokenProxy other = (AbstractTokenProxy) obj;
		if (getId() == null) {
			if (other.getId() != null) {
				return false;
			}
		} else if (!getId().equals(other.getId())) {
			return false;
		}
		return true;
	}

}

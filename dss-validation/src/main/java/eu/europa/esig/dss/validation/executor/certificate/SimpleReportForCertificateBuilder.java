/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.executor.certificate;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlConclusion;
import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustServiceProvider;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlRevocation;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSubject;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlTrustAnchor;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlValidationPolicy;
import eu.europa.esig.dss.utils.Utils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Builds a SimpleReport for a certificate validation
 */
public class SimpleReportForCertificateBuilder {

	/** The diagnostic data */
	private final DiagnosticData diagnosticData;

	/** The detailed report */
	private final DetailedReport detailedReport;

	/** The validation policy */
	private final ValidationPolicy policy;

	/** The validation time */
	private final Date currentTime;

	/** The id of a certificate to be validated */
	private final String certificateId;

	/**
	 * Default constructor
	 *
	 * @param diagnosticData {@link DiagnosticData}
	 * @param detailedReport {@link DetailedReport}
	 * @param policy {@link ValidationPolicy}
	 * @param currentTime {@link Date} validation time
	 * @param certificateId {@link String} if od certificate to be validated
	 */
	public SimpleReportForCertificateBuilder(DiagnosticData diagnosticData, DetailedReport detailedReport,
											 ValidationPolicy policy, Date currentTime, String certificateId) {
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
		this.policy = policy;
		this.currentTime = currentTime;
		this.certificateId = certificateId;
	}

	/**
	 * Builds {@code XmlSimpleCertificateReport}
	 *
	 * @return {@link XmlSimpleCertificateReport}
	 */
	public XmlSimpleCertificateReport build() {
		final XmlSimpleCertificateReport simpleReport = new XmlSimpleCertificateReport();

		addPolicyNode(simpleReport);
		addValidationTime(simpleReport);

		simpleReport.setValidationTime(currentTime);
		List<XmlChainItem> chain = new ArrayList<>();

		CertificateWrapper certificate = diagnosticData.getUsedCertificateById(certificateId);
		XmlChainItem firstChainItem = getChainItem(certificate);
		addQualifications(firstChainItem, certificate);
		chain.add(firstChainItem);

		List<CertificateWrapper> certificateChain = certificate.getCertificateChain();
		for (CertificateWrapper cert : certificateChain) {
			chain.add(getChainItem(cert));
		}
		simpleReport.setChain(chain);

		return simpleReport;
	}

	private void addPolicyNode(XmlSimpleCertificateReport report) {
		XmlValidationPolicy xmlPolicy = new XmlValidationPolicy();
		xmlPolicy.setPolicyName(policy.getPolicyName());
		xmlPolicy.setPolicyDescription(policy.getPolicyDescription());
		report.setValidationPolicy(xmlPolicy);
	}

	private void addValidationTime(XmlSimpleCertificateReport report) {
		report.setValidationTime(currentTime);
	}

	private XmlChainItem getChainItem(CertificateWrapper certificate) {
		XmlChainItem item = new XmlChainItem();
		item.setId(certificate.getId());
		item.setSubject(getSubject(certificate));
		CertificateWrapper signingCertificate = certificate.getSigningCertificate();
		if (signingCertificate != null) {
			item.setIssuerId(signingCertificate.getId());
		}
		item.setNotBefore(certificate.getNotBefore());
		item.setNotAfter(certificate.getNotAfter());
		item.setKeyUsages(certificate.getKeyUsages());
		item.setExtendedKeyUsages(getReadable(certificate.getExtendedKeyUsages()));
		item.setAiaUrls(emptyToNull(certificate.getCAIssuersAccessUrls()));
		item.setOcspUrls(emptyToNull(certificate.getOCSPAccessUrls()));
		item.setCrlUrls(emptyToNull(certificate.getCRLDistributionPoints()));
		item.setCpsUrls(emptyToNull(certificate.getCpsUrls()));
		item.setPdsUrls(null);

		XmlRevocation revocation = new XmlRevocation();
		CertificateRevocationWrapper revocationData = diagnosticData.getLatestRevocationDataForCertificate(certificate);
		if (revocationData != null) {
			revocation.setThisUpdate(revocationData.getThisUpdate());
			revocation.setRevocationDate(revocationData.getRevocationDate());
			revocation.setRevocationReason(revocationData.getReason());
		}
		item.setRevocation(revocation);

		if (certificate.isTrusted()) {
			List<XmlTrustServiceProvider> trustServiceProviders = filterByCertificateId(certificate.getTrustServiceProviders(), certificate.getId());
			List<XmlTrustAnchor> trustAnchors = new ArrayList<>();
			for (XmlTrustServiceProvider xmlTrustServiceProvider : trustServiceProviders) {
				List<XmlTrustService> trustServices = xmlTrustServiceProvider.getTrustServices();
				Set<String> uniqueServiceNames = getUniqueServiceNames(trustServices);
				for (String serviceName : uniqueServiceNames) {
					XmlTrustAnchor trustAnchor = new XmlTrustAnchor();
					if (xmlTrustServiceProvider.getTL() != null) {
						trustAnchor.setCountryCode(xmlTrustServiceProvider.getTL().getCountryCode());
						trustAnchor.setTslType(xmlTrustServiceProvider.getTL().getTSLType());
					}
					trustAnchor.setTrustServiceProvider(getEnOrFirst(xmlTrustServiceProvider.getTSPNames()));
					List<String> tspRegistrationIdentifiers = xmlTrustServiceProvider.getTSPRegistrationIdentifiers();
					if (Utils.isCollectionNotEmpty(tspRegistrationIdentifiers)) {
						trustAnchor.setTrustServiceProviderRegistrationId(tspRegistrationIdentifiers.get(0));
					}
					trustAnchor.setTrustServiceName(serviceName);
					trustAnchors.add(trustAnchor);
				}
			}
			item.setTrustAnchors(trustAnchors);
			item.setTrustStartDate(certificate.getTrustStartDate());
			item.setTrustSunsetDate(certificate.getTrustSunsetDate());
		} else {
			item.setTrustAnchors(null);
		}

		XmlConclusion conclusion = detailedReport.getCertificateXCVConclusion(certificate.getId());
		item.setIndication(conclusion.getIndication());
		item.setSubIndication(conclusion.getSubIndication());

		XmlDetails validationDetails = getX509ValidationDetails(certificate.getId());
		if (isNotEmpty(validationDetails)) {
			item.setX509ValidationDetails(validationDetails);
		}

		return item;
	}

	private String getEnOrFirst(List<XmlLangAndValue> langAndValues) {
		if (Utils.isCollectionNotEmpty(langAndValues)) {
			for (XmlLangAndValue langAndValue : langAndValues) {
				if (langAndValue.getLang() != null && "en".equalsIgnoreCase(langAndValue.getLang())) {
					return langAndValue.getValue();
				}
			}
			return langAndValues.get(0).getValue();
		}
		return null;
	}

	private List<XmlTrustServiceProvider> filterByCertificateId(List<XmlTrustServiceProvider> trustServiceProviders, String certificateId) {
		List<XmlTrustServiceProvider> result = new ArrayList<>();
		for (XmlTrustServiceProvider xmlTrustServiceProvider : trustServiceProviders) {
			List<XmlTrustService> trustServices = xmlTrustServiceProvider.getTrustServices();
			boolean foundCertId = false;
			for (XmlTrustService xmlTrustService : trustServices) {
				if (Utils.areStringsEqual(certificateId, xmlTrustService.getServiceDigitalIdentifier().getId())) {
					foundCertId = true;
					break;
				}
			}
			if (foundCertId) {
				result.add(xmlTrustServiceProvider);
			}
		}
		return result;
	}

	private List<String> getReadable(List<XmlOID> oids) {
		if (Utils.isCollectionNotEmpty(oids)) {
			List<String> result = new ArrayList<>();
			for (XmlOID xmlOID : oids) {
				if (Utils.isStringNotEmpty(xmlOID.getDescription())) {
					result.add(xmlOID.getDescription());
				} else {
					result.add(xmlOID.getValue());
				}
			}
			return result;
		}
		return null;
	}

	private Set<String> getUniqueServiceNames(List<XmlTrustService> trustServices) {
		Set<String> result = new HashSet<>();
		for (XmlTrustService xmlTrustService : trustServices) {
			result.add(getEnOrFirst(xmlTrustService.getServiceNames()));
		}
		return result;
	}

	private XmlSubject getSubject(CertificateWrapper certificate) {
		XmlSubject subject = new XmlSubject();
		subject.setCommonName(certificate.getCommonName());
		subject.setPseudonym(certificate.getPseudo());
		subject.setSurname(certificate.getSurname());
		subject.setGivenName(certificate.getGivenName());
		subject.setOrganizationName(certificate.getOrganizationName());
		subject.setOrganizationUnit(certificate.getOrganizationalUnit());
		subject.setEmail(certificate.getEmail());
		subject.setLocality(certificate.getLocality());
		subject.setState(certificate.getState());
		subject.setCountry(certificate.getCountryName());
		return subject;
	}

	private List<String> emptyToNull(List<String> listUrls) {
		if (Utils.isCollectionEmpty(listUrls)) {
			return null;
		}
		return listUrls;
	}

	private void addQualifications(XmlChainItem firstChainItem, CertificateWrapper certificate) {
		firstChainItem.setQualificationAtIssuance(detailedReport.getCertificateQualificationAtIssuance(certificateId));
		firstChainItem.setQualificationAtValidation(detailedReport.getCertificateQualificationAtValidation(certificateId));

		XmlDetails qualificationDetailsAtIssuanceTime = getCertificateQualificationDetailsAtIssuanceTime(certificate.getId());
		if (isNotEmpty(qualificationDetailsAtIssuanceTime)) {
			firstChainItem.setQualificationDetailsAtIssuance(qualificationDetailsAtIssuanceTime);
		}
		XmlDetails qualificationDetailsAtValidationTime = getCertificateQualificationDetailsAtValidationTime(certificate.getId());
		if (isNotEmpty(qualificationDetailsAtValidationTime)) {
			firstChainItem.setQualificationDetailsAtValidation(qualificationDetailsAtValidationTime);
		}

		Boolean enactedMRA = null;
		List<TrustServiceWrapper> trustServices = certificate.getTrustServices();
		for (TrustServiceWrapper trustServiceWrapper : trustServices) {
			if (trustServiceWrapper.isEnactedMRA()) {
				enactedMRA = true;
				break;
			}
		}
		firstChainItem.setEnactedMRA(enactedMRA);
	}

	private XmlDetails getX509ValidationDetails(String tokenId) {
		XmlDetails validationDetails = new XmlDetails();
		validationDetails.getError().addAll(convert(detailedReport.getAdESValidationErrors(tokenId)));
		validationDetails.getWarning().addAll(convert(detailedReport.getAdESValidationWarnings(tokenId)));
		validationDetails.getInfo().addAll(convert(detailedReport.getAdESValidationInfos(tokenId)));
		return validationDetails;
	}

	private XmlDetails getCertificateQualificationDetailsAtIssuanceTime(String tokenId) {
		XmlDetails qualificationDetails = new XmlDetails();
		qualificationDetails.getError().addAll(convert(detailedReport.getCertificateQualificationErrorsAtIssuanceTime(tokenId)));
		qualificationDetails.getWarning().addAll(convert(detailedReport.getCertificateQualificationWarningsAtIssuanceTime(tokenId)));
		qualificationDetails.getInfo().addAll(convert(detailedReport.getCertificateQualificationInfosAtIssuanceTime(tokenId)));
		return qualificationDetails;
	}

	private XmlDetails getCertificateQualificationDetailsAtValidationTime(String tokenId) {
		XmlDetails qualificationDetails = new XmlDetails();
		qualificationDetails.getError().addAll(convert(detailedReport.getCertificateQualificationErrorsAtValidationTime(tokenId)));
		qualificationDetails.getWarning().addAll(convert(detailedReport.getCertificateQualificationWarningsAtValidationTime(tokenId)));
		qualificationDetails.getInfo().addAll(convert(detailedReport.getCertificateQualificationInfosAtValidationTime(tokenId)));
		return qualificationDetails;
	}

	private List<XmlMessage> convert(Collection<Message> messages) {
		return messages.stream().map(m -> {
			XmlMessage xmlMessage = new XmlMessage();
			xmlMessage.setKey(m.getKey());
			xmlMessage.setValue(m.getValue());
			return xmlMessage;
		}).collect(Collectors.toList());
	}

	private boolean isNotEmpty(XmlDetails details) {
		return Utils.isCollectionNotEmpty(details.getError()) || Utils.isCollectionNotEmpty(details.getWarning()) ||
				Utils.isCollectionNotEmpty(details.getInfo());
	}

}

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
import eu.europa.esig.dss.detailedreport.jaxb.XmlRevocationInformation;
import eu.europa.esig.dss.detailedreport.jaxb.XmlSubXCV;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TrustServiceWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlLangAndValue;
import eu.europa.esig.dss.diagnostic.jaxb.XmlOID;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustService;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustServiceProvider;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedEntity;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTrustedEntityService;
import eu.europa.esig.dss.enumerations.CertificateApprovalStatus;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlCertificateApprovalStatus;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlCertificateApprovalStatusAtIssuanceTime;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlCertificateApprovalStatusAtValidationTime;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlChainItem;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlConnectionDetails;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlDetails;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlMessage;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlRevocation;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSignature;
import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSignatureScope;
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

		CertificateWrapper certificate = diagnosticData.getUsedCertificateById(certificateId);
		XmlChainItem targetCertificate = getChainItem(certificate, false);
		addQualifications(targetCertificate, certificate);
		addQWACValidationDetails(targetCertificate, certificate);
		addCertificateApprovalStatuss(targetCertificate, certificate);
		simpleReport.setCertificate(targetCertificate);

		List<XmlChainItem> chain = new ArrayList<>();
		boolean trustAnchorReached = false;
		List<CertificateWrapper> certificateChain = certificate.getCertificateChain();
		for (CertificateWrapper cert : certificateChain) {
			trustAnchorReached |= cert.isTrusted();
			chain.add(getChainItem(cert, trustAnchorReached));
		}
		targetCertificate.setChain(chain);

		addConnectionDetails(simpleReport);

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

	private XmlChainItem getChainItem(CertificateWrapper certificate, boolean trustAnchorReached) {
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
		XmlRevocationInformation revocationInfo = getCertificateRevocationInfo(certificate.getId());
		if (revocationInfo != null) {
			revocation.setThisUpdate(revocationInfo.getThisUpdate());
			revocation.setRevocationDate(revocationInfo.getRevocationDate());
			revocation.setRevocationReason(revocationInfo.getReason());
		}
		item.setRevocation(revocation);

		if (certificate.isTrusted()) {
			final List<XmlTrustAnchor> trustAnchors = new ArrayList<>();

			List<XmlTrustServiceProvider> trustServiceProviders = filterTSPsByCertificateId(certificate.getTrustServiceProviders(), certificate.getId());
			for (XmlTrustServiceProvider xmlTrustServiceProvider : trustServiceProviders) {
				List<XmlTrustService> trustServices = xmlTrustServiceProvider.getTrustServices();
				Set<String> uniqueServiceNames = getUniqueServiceNames(trustServices);
				for (String serviceName : uniqueServiceNames) {
					XmlTrustAnchor trustAnchor = new XmlTrustAnchor();
					if (xmlTrustServiceProvider.getTL() != null) {
						trustAnchor.setCountryCode(xmlTrustServiceProvider.getTL().getCountryCode());
						trustAnchor.setTslType(xmlTrustServiceProvider.getTL().getType());
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
			// NOTE: separate ?
			List<XmlTrustedEntity> trustedEntities = filterTEsByCertificateId(certificate.getTrustedEntities(), certificate.getId());
			for (XmlTrustedEntity xmlTrustedEntity : trustedEntities) {
				List<XmlTrustedEntityService> trustedEntityServices = xmlTrustedEntity.getTrustedEntityServices();
				Set<String> uniqueServiceNames = getUniqueServiceNames(trustedEntityServices);
				for (String serviceName : uniqueServiceNames) {
					XmlTrustAnchor trustAnchor = new XmlTrustAnchor();
					if (xmlTrustedEntity.getLoTE() != null) {
						trustAnchor.setCountryCode(xmlTrustedEntity.getLoTE().getCountryCode());
						trustAnchor.setTslType(xmlTrustedEntity.getLoTE().getType());
					}
					trustAnchor.setTrustServiceProvider(getEnOrFirst(xmlTrustedEntity.getNames()));
					List<String> registrationIdentifiers = xmlTrustedEntity.getRegistrationIdentifiers();
					if (Utils.isCollectionNotEmpty(registrationIdentifiers)) {
						trustAnchor.setTrustServiceProviderRegistrationId(registrationIdentifiers.get(0));
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
		if (conclusion != null) {
			item.setIndication(conclusion.getIndication());
			item.setSubIndication(conclusion.getSubIndication());

		} else if (certificate.isTrusted() || trustAnchorReached) {
			item.setIndication(Indication.PASSED);

		} else {
			// if certificate was not validated or not trusted
			item.setIndication(Indication.INDETERMINATE);
			item.setSubIndication(SubIndication.NO_CERTIFICATE_CHAIN_FOUND);
		}

		XmlDetails validationDetails = getValidationDetails(certificate.getId());
		if (isNotEmpty(validationDetails)) {
			item.setX509ValidationDetails(validationDetails);
		}

		return item;
	}

	private XmlRevocationInformation getCertificateRevocationInfo(String certificateId) {
		XmlSubXCV xmlSubXCV = detailedReport.getCertificateXCV(certificateId);
		if (xmlSubXCV != null) {
			return xmlSubXCV.getRevocationInfo();
		}
		return null;
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

	private List<XmlTrustServiceProvider> filterTSPsByCertificateId(List<XmlTrustServiceProvider> trustServiceProviders, String certificateId) {
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

	private List<XmlTrustedEntity> filterTEsByCertificateId(List<XmlTrustedEntity> trustedEntities, String certificateId) {
		List<XmlTrustedEntity> result = new ArrayList<>();
		for (XmlTrustedEntity xmlTrustedEntity : trustedEntities) {
			List<XmlTrustedEntityService> trustedEntityServices = xmlTrustedEntity.getTrustedEntityServices();
			boolean foundCertId = false;
			for (XmlTrustedEntityService xmlTrustedService : trustedEntityServices) {
				if (Utils.areStringsEqual(certificateId, xmlTrustedService.getServiceDigitalIdentifier().getId())) {
					foundCertId = true;
					break;
				}
			}
			if (foundCertId) {
				result.add(xmlTrustedEntity);
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

	private Set<String> getUniqueServiceNames(List<? extends XmlTrustedEntityService> trustServices) {
		Set<String> result = new HashSet<>();
		for (XmlTrustedEntityService xmlTrustService : trustServices) {
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

	private void addQualifications(XmlChainItem chainItem, CertificateWrapper certificate) {
		chainItem.setQualificationAtIssuance(detailedReport.getCertificateQualificationAtIssuance(certificate.getId()));
		chainItem.setQualificationAtValidation(detailedReport.getCertificateQualificationAtValidation(certificate.getId()));

		XmlDetails qualificationDetailsAtIssuanceTime = getCertificateQualificationDetailsAtIssuanceTime(certificate.getId());
		if (isNotEmpty(qualificationDetailsAtIssuanceTime)) {
			chainItem.setQualificationDetailsAtIssuance(qualificationDetailsAtIssuanceTime);
		}
		XmlDetails qualificationDetailsAtValidationTime = getCertificateQualificationDetailsAtValidationTime(certificate.getId());
		if (isNotEmpty(qualificationDetailsAtValidationTime)) {
			chainItem.setQualificationDetailsAtValidation(qualificationDetailsAtValidationTime);
		}

		Boolean enactedMRA = null;
		List<TrustServiceWrapper> trustServices = certificate.getTrustServices();
		for (TrustServiceWrapper trustServiceWrapper : trustServices) {
			if (trustServiceWrapper.isEnactedMRA()) {
				enactedMRA = true;
				break;
			}
		}
		chainItem.setEnactedMRA(enactedMRA);
	}

	private void addQWACValidationDetails(XmlChainItem chainItem, CertificateWrapper certificate) {
		addQWACProfile(chainItem, certificate);
		addTLSBindingSignature(chainItem);
	}

	private void addQWACProfile(XmlChainItem chainItem, CertificateWrapper certificate) {
		chainItem.setQwacProfile(detailedReport.getCertificateQWACProfile(certificate.getId()));
		XmlDetails qwacValidationDetails = getQWACValidationDetails(certificate.getId());
		if (isNotEmpty(qwacValidationDetails)) {
			chainItem.setQwacDetails(qwacValidationDetails);
		}
	}

	private void addCertificateApprovalStatuss(XmlChainItem chainItem, CertificateWrapper certificate) {
		chainItem.setCertificateApprovalStatusAtIssuanceTime(getCertificateApprovalStatusAtIssuanceTime(certificate));
		chainItem.setCertificateApprovalStatusAtValidationTime(getCertificateApprovalStatusAtValidationTime(certificate));
	}

	private XmlCertificateApprovalStatusAtIssuanceTime getCertificateApprovalStatusAtIssuanceTime(CertificateWrapper certificate) {
		List<CertificateApprovalStatus> certificateApprovalStatussAtIssuanceTime = detailedReport.getCertificateApprovalStatussAtIssuanceTime(certificate.getId());
		if (Utils.isCollectionEmpty(certificateApprovalStatussAtIssuanceTime)) {
			return null;
		}

		XmlCertificateApprovalStatusAtIssuanceTime xmlCertificateApprovalStatusAtTime = new XmlCertificateApprovalStatusAtIssuanceTime();
		for (CertificateApprovalStatus certificateApprovalStatus : certificateApprovalStatussAtIssuanceTime) {
			XmlCertificateApprovalStatus xmlCertificateApprovalStatus = new XmlCertificateApprovalStatus();
			xmlCertificateApprovalStatus.setListType(certificateApprovalStatus.getListType());
			xmlCertificateApprovalStatus.setServiceTypeIdentifier(certificateApprovalStatus.getServiceTypeIdentifier());
			xmlCertificateApprovalStatus.setServiceStatus(certificateApprovalStatus.getServiceStatus());
			xmlCertificateApprovalStatus.setLabel(certificateApprovalStatus.getLabel());
			xmlCertificateApprovalStatus.setDetails(getCertificateApprovalStatusDetailsAtIssuanceTime(certificate.getId(), certificateApprovalStatus));

			xmlCertificateApprovalStatusAtTime.getCertificateApprovalStatus().add(xmlCertificateApprovalStatus);
		}
		return xmlCertificateApprovalStatusAtTime;
	}

	private XmlCertificateApprovalStatusAtValidationTime getCertificateApprovalStatusAtValidationTime(CertificateWrapper certificate) {
		List<CertificateApprovalStatus> certificateApprovalStatussAtIssuanceTime = detailedReport.getCertificateApprovalStatussAtValidationTime(certificate.getId());
		if (Utils.isCollectionEmpty(certificateApprovalStatussAtIssuanceTime)) {
			return null;
		}

		XmlCertificateApprovalStatusAtValidationTime xmlCertificateApprovalStatusAtTime = new XmlCertificateApprovalStatusAtValidationTime();
		for (CertificateApprovalStatus certificateApprovalStatus : certificateApprovalStatussAtIssuanceTime) {
			XmlCertificateApprovalStatus xmlCertificateApprovalStatus = new XmlCertificateApprovalStatus();
			xmlCertificateApprovalStatus.setListType(certificateApprovalStatus.getListType());
			xmlCertificateApprovalStatus.setServiceTypeIdentifier(certificateApprovalStatus.getServiceTypeIdentifier());
			xmlCertificateApprovalStatus.setServiceStatus(certificateApprovalStatus.getServiceStatus());
			xmlCertificateApprovalStatus.setLabel(certificateApprovalStatus.getLabel());
			xmlCertificateApprovalStatus.setDetails(getCertificateApprovalStatusDetailsAtValidationTime(certificate.getId(), certificateApprovalStatus));

			xmlCertificateApprovalStatusAtTime.getCertificateApprovalStatus().add(xmlCertificateApprovalStatus);
		}
		return xmlCertificateApprovalStatusAtTime;
	}

	private XmlDetails getValidationDetails(String tokenId) {
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

	private XmlDetails getQWACValidationDetails(String tokenId) {
		XmlDetails qualificationDetails = new XmlDetails();
		qualificationDetails.getError().addAll(convert(detailedReport.getQWACValidationErrors(tokenId)));
		qualificationDetails.getWarning().addAll(convert(detailedReport.getQWACValidationWarnings(tokenId)));
		qualificationDetails.getInfo().addAll(convert(detailedReport.getQWACValidationInfos(tokenId)));
		return qualificationDetails;
	}

	private XmlDetails getCertificateApprovalStatusDetailsAtIssuanceTime(String tokenId, CertificateApprovalStatus certificateApprovalStatus) {
		XmlDetails usageDetails = new XmlDetails();
		usageDetails.getError().addAll(convert(detailedReport.getCertificateApprovalStatusErrorsAtIssuanceTime(tokenId, certificateApprovalStatus)));
		usageDetails.getWarning().addAll(convert(detailedReport.getCertificateApprovalStatusWarningsAtIssuanceTime(tokenId, certificateApprovalStatus)));
		usageDetails.getInfo().addAll(convert(detailedReport.getCertificateApprovalStatusInfosAtIssuanceTime(tokenId, certificateApprovalStatus)));
		return usageDetails;
	}

	private XmlDetails getCertificateApprovalStatusDetailsAtValidationTime(String tokenId, CertificateApprovalStatus certificateApprovalStatus) {
		XmlDetails usageDetails = new XmlDetails();
		usageDetails.getError().addAll(convert(detailedReport.getCertificateApprovalStatusErrorsAtValidationTime(tokenId, certificateApprovalStatus)));
		usageDetails.getWarning().addAll(convert(detailedReport.getCertificateApprovalStatusWarningsAtValidationTime(tokenId, certificateApprovalStatus)));
		usageDetails.getInfo().addAll(convert(detailedReport.getCertificateApprovalStatusInfosAtValidationTime(tokenId, certificateApprovalStatus)));
		return usageDetails;
	}

	private void addTLSBindingSignature(XmlChainItem chainItem) {
		SignatureWrapper bindingSignature = diagnosticData.getTLSCertificateBindingSignature();
		if (bindingSignature != null) {
			XmlSignature xmlSignature = new XmlSignature();
			xmlSignature.setId(bindingSignature.getId());
			xmlSignature.setUrl(diagnosticData.getTLSCertificateBindingUrl());
			xmlSignature.setSigningTime(bindingSignature.getClaimedSigningTime());
			xmlSignature.setSignatureFormat(bindingSignature.getSignatureFormat());
			addSignatureScope(bindingSignature, xmlSignature);
			addFinalIndication(bindingSignature, xmlSignature);
			addAdESValidationDetails(bindingSignature, xmlSignature);
			addChain(bindingSignature, xmlSignature);

			chainItem.setTLSBindingSignature(xmlSignature);
		}
	}

	private void addSignatureScope(final SignatureWrapper signature, final XmlSignature xmlSignature) {
		List<eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope> signatureScopes = signature.getSignatureScopes();
		if (Utils.isCollectionNotEmpty(signatureScopes)) {
			for (eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope signatureScope : signatureScopes) {
				xmlSignature.getSignatureScope().add(getXmlSignatureScope(signatureScope));
			}
		}
	}

	private void addFinalIndication(final SignatureWrapper signature, final XmlSignature xmlSignature) {
		xmlSignature.setIndication(detailedReport.getFinalIndication(signature.getId()));
		SubIndication subIndication = detailedReport.getFinalSubIndication(signature.getId());
		if (subIndication != null) {
			xmlSignature.setSubIndication(subIndication);
		}
	}

	private void addAdESValidationDetails(final SignatureWrapper signature, final XmlSignature xmlSignature) {
		XmlDetails validationDetails = getValidationDetails(signature.getId());
		if (isNotEmpty(validationDetails)) {
			xmlSignature.setAdESValidationDetails(validationDetails);
		}
	}

	private XmlSignatureScope getXmlSignatureScope(eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope signatureScope) {
		XmlSignatureScope xmlSignatureScope = new XmlSignatureScope();
		xmlSignatureScope.setId(signatureScope.getSignerData().getId());
		xmlSignatureScope.setName(signatureScope.getName());
		xmlSignatureScope.setScope(signatureScope.getScope());
		xmlSignatureScope.setValue(signatureScope.getDescription());
		return xmlSignatureScope;
	}

	private void addChain(SignatureWrapper bindingSignature, XmlSignature xmlSignature) {
		List<CertificateWrapper> certificateChain = bindingSignature.getCertificateChain();
		if (Utils.isCollectionEmpty(certificateChain)) {
			return;
		}

		boolean trustAnchorReached = false;
		final List<XmlChainItem> chain = new ArrayList<>();
		for (CertificateWrapper cert : certificateChain) {
			trustAnchorReached |= cert.isTrusted();
			XmlChainItem chainItem = getChainItem(cert, trustAnchorReached);
			if (bindingSignature.getSigningCertificate() != null
					&& bindingSignature.getSigningCertificate().getId().equals(cert.getId())) {
				addQualifications(chainItem, cert);
				addQWACProfile(chainItem, cert);
			}
			chain.add(chainItem);
		}
		xmlSignature.setChain(chain);
	}

	private List<XmlMessage> convert(Collection<Message> messages) {
		return messages.stream().map(m -> {
			XmlMessage xmlMessage = new XmlMessage();
			xmlMessage.setKey(m.getKey());
			xmlMessage.setValue(m.getValue());
			return xmlMessage;
		}).collect(Collectors.toList());
	}

	private void addConnectionDetails(XmlSimpleCertificateReport simpleReport) {
		if (diagnosticData.getWebsiteUrl() != null) {
			XmlConnectionDetails xmlConnectionDetails = new XmlConnectionDetails();
			xmlConnectionDetails.setUrl(diagnosticData.getWebsiteUrl());
			xmlConnectionDetails.setTLSCertificateBindingLink(diagnosticData.getTLSCertificateBindingUrl());
			simpleReport.setConnectionDetails(xmlConnectionDetails);
		}
	}

	private boolean isNotEmpty(XmlDetails details) {
		return Utils.isCollectionNotEmpty(details.getError()) || Utils.isCollectionNotEmpty(details.getWarning()) ||
				Utils.isCollectionNotEmpty(details.getInfo());
	}

}

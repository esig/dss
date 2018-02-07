package eu.europa.esig.dss.validation.executor;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedService;
import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProvider;
import eu.europa.esig.dss.jaxb.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.jaxb.simplecertificatereport.XmlChainItem;
import eu.europa.esig.dss.jaxb.simplecertificatereport.XmlRevocation;
import eu.europa.esig.dss.jaxb.simplecertificatereport.XmlSubject;
import eu.europa.esig.dss.jaxb.simplecertificatereport.XmlTrustAnchor;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.dss.validation.reports.wrapper.RevocationWrapper;

public class SimpleReportForCertificateBuilder {

	private final DiagnosticData diagnosticData;
	private final DetailedReport detailedReport;
	private final Date currentTime;
	private final String certificateId;

	public SimpleReportForCertificateBuilder(DiagnosticData diagnosticData, DetailedReport detailedReport, Date currentTime, String certificateId) {
		this.diagnosticData = diagnosticData;
		this.detailedReport = detailedReport;
		this.currentTime = currentTime;
		this.certificateId = certificateId;
	}

	public SimpleCertificateReport build() {
		SimpleCertificateReport simpleReport = new SimpleCertificateReport();
		simpleReport.setValidationTime(currentTime);
		List<XmlChainItem> chain = new ArrayList<XmlChainItem>();

		CertificateWrapper certificate = diagnosticData.getUsedCertificateById(certificateId);
		XmlChainItem firstChainItem = getChainItem(certificate);
		addQualifications(firstChainItem);
		chain.add(firstChainItem);

		List<String> certificateChainIds = certificate.getCertificateChainIds();
		for (String certId : certificateChainIds) {
			CertificateWrapper issuer = diagnosticData.getUsedCertificateById(certId);
			chain.add(getChainItem(issuer));
		}
		simpleReport.setChain(chain);

		return simpleReport;
	}

	private XmlChainItem getChainItem(CertificateWrapper certificate) {
		XmlChainItem item = new XmlChainItem();
		item.setId(certificate.getId());
		item.setSubject(getSubject(certificate));
		item.setIssuerId(certificate.getFirstChainCertificateId());
		item.setNotBefore(certificate.getNotBefore());
		item.setNotAfter(certificate.getNotAfter());
		item.setAiaUrls(emptyToNull(certificate.getAuthorityInformationAccessUrls()));
		item.setOcspUrls(emptyToNull(certificate.getOCSPAccessUrls()));
		item.setCrlUrls(emptyToNull(certificate.getCRLDistributionPoints()));
		item.setCpsUrls(emptyToNull(certificate.getCpsUrls()));
		item.setPdsUrls(null);

		RevocationWrapper revocationData = certificate.getLatestRevocationData();
		if (revocationData != null && revocationData.getRevocationDate() != null) {
			XmlRevocation revocation = new XmlRevocation();
			revocation.setRevocationDate(revocationData.getRevocationDate());
			revocation.setRevocationReason(revocationData.getReason());
			item.setRevocation(revocation);
		}

		if (certificate.isTrusted()) {
			List<XmlTrustedServiceProvider> trustServiceProviders = certificate.getTrustServiceProviders();
			List<XmlTrustAnchor> trustAnchors = new ArrayList<XmlTrustAnchor>();
			for (XmlTrustedServiceProvider xmlTrustedServiceProvider : trustServiceProviders) {
				List<XmlTrustedService> trustedServices = xmlTrustedServiceProvider.getTrustedServices();
				Set<String> uniqueServiceNames = getUniqueServiceNames(trustedServices);
				for (String serviceName : uniqueServiceNames) {
					XmlTrustAnchor trustAnchor = new XmlTrustAnchor();
					trustAnchor.setCountryCode(xmlTrustedServiceProvider.getCountryCode());
					trustAnchor.setTrustServiceProvider(xmlTrustedServiceProvider.getTSPName());
					trustAnchor.setTrustServiceProviderRegistrationId(xmlTrustedServiceProvider.getTSPRegistrationIdentifier());
					trustAnchor.setTrustServiceName(serviceName);
					trustAnchors.add(trustAnchor);
				}
			}
			item.setTrustAnchors(trustAnchors);
		} else {
			item.setTrustAnchors(null);
		}

		return item;
	}

	private Set<String> getUniqueServiceNames(List<XmlTrustedService> trustedServices) {
		Set<String> result = new HashSet<String>();
		for (XmlTrustedService xmlTrustedService : trustedServices) {
			result.add(xmlTrustedService.getServiceName());
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
		subject.setCountry(certificate.getCountryName());
		return subject;
	}

	private List<String> emptyToNull(List<String> listUrls) {
		if (Utils.isCollectionEmpty(listUrls)) {
			return null;
		}
		return listUrls;
	}

	private void addQualifications(XmlChainItem firstChainItem) {
		firstChainItem.setQualificationAtIssuance(detailedReport.getCertificateQualificationAtIssuance());
		firstChainItem.setQualificationAtValidation(detailedReport.getCertificateQualificationAtValidation());
	}

}

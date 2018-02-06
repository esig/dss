package eu.europa.esig.dss.validation.executor;

import java.util.Date;
import java.util.List;

import eu.europa.esig.dss.jaxb.diagnostic.XmlTrustedServiceProvider;
import eu.europa.esig.dss.jaxb.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.jaxb.simplecertificatereport.XmlChainItem;
import eu.europa.esig.dss.jaxb.simplecertificatereport.XmlRevocation;
import eu.europa.esig.dss.jaxb.simplecertificatereport.XmlTrustAnchor;
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

		CertificateWrapper certificate = diagnosticData.getUsedCertificateById(certificateId);
		XmlChainItem firstChainItem = getChainItem(certificate);
		addQualifications(firstChainItem);
		simpleReport.getChain().add(firstChainItem);

		List<String> certificateChainIds = certificate.getCertificateChainIds();
		for (String certId : certificateChainIds) {
			CertificateWrapper issuer = diagnosticData.getUsedCertificateById(certId);
			simpleReport.getChain().add(getChainItem(issuer));
		}

		return simpleReport;
	}

	private XmlChainItem getChainItem(CertificateWrapper certificate) {
		XmlChainItem item = new XmlChainItem();
		item.setId(certificate.getId());
		item.setSubject(certificate.getCommonName());
		item.setIssuerId(certificate.getFirstChainCertificateId());
		item.setNotBefore(certificate.getNotBefore());
		item.setNotAfter(certificate.getNotAfter());
		item.getAiaUrls().addAll(certificate.getAuthorityInformationAccessUrls());
		item.getOcspUrls().addAll(certificate.getOCSPAccessUrls());
		item.getCrlUrls().addAll(certificate.getCRLDistributionPoints());
		item.getCpsUrls().addAll(certificate.getCpsUrls());

		RevocationWrapper revocationData = certificate.getLatestRevocationData();
		if (revocationData != null && revocationData.getRevocationDate() != null) {
			XmlRevocation revocation = new XmlRevocation();
			revocation.setRevocationDate(revocationData.getRevocationDate());
			revocation.setRevocationReason(revocationData.getReason());
			item.setRevocation(revocation);
		}

		if (certificate.isTrusted()) {
			List<XmlTrustedServiceProvider> trustServiceProviders = certificate.getTrustServiceProviders();
			for (XmlTrustedServiceProvider xmlTrustedServiceProvider : trustServiceProviders) {
				XmlTrustAnchor trustAnchor = new XmlTrustAnchor();
				trustAnchor.setCountryCode(xmlTrustedServiceProvider.getCountryCode());
				trustAnchor.setTrustServiceProvider(xmlTrustedServiceProvider.getTSPName());
				trustAnchor.setTrustServiceProviderRegistrationId(xmlTrustedServiceProvider.getTSPRegistrationIdentifier());
				trustAnchor.setTrustServiceName(xmlTrustedServiceProvider.getTSPServiceName());
				item.getTrustAnchor().add(trustAnchor);
			}
		}

		return item;
	}

	private void addQualifications(XmlChainItem firstChainItem) {
		firstChainItem.setQualificationAtIssuance(detailedReport.getCertificateQualificationAtIssuance());
		firstChainItem.setQualificationAtValidation(detailedReport.getCertificateQualificationAtValidation());
	}

}

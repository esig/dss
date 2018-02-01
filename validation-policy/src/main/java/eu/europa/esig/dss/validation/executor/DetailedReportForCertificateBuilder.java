package eu.europa.esig.dss.validation.executor;

import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.detailedreport.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.process.qualification.certificate.CertificateQualificationBlock;
import eu.europa.esig.dss.validation.reports.wrapper.CertificateWrapper;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class DetailedReportForCertificateBuilder extends AbstractDetailedReportBuilder {

	private final String certificateId;

	public DetailedReportForCertificateBuilder(DiagnosticData diagnosticData, ValidationPolicy policy, Date currentTime, String certificateId) {
		super(diagnosticData, policy, currentTime);
		this.certificateId = certificateId;
	}

	DetailedReport build() {

		DetailedReport detailedReport = init();

		CertificateWrapper certificate = diagnosticData.getUsedCertificateById(certificateId);

		Map<String, XmlBasicBuildingBlocks> bbbs = new HashMap<String, XmlBasicBuildingBlocks>();
		process(Collections.singleton(certificate), Context.CERTIFICATE, bbbs);
		detailedReport.getBasicBuildingBlocks().addAll(bbbs.values());

		XmlBasicBuildingBlocks basicBuildingBlocks = bbbs.get(certificate.getId());

		CertificateQualificationBlock cqb = new CertificateQualificationBlock(basicBuildingBlocks.getConclusion(), currentTime, certificate,
				detailedReport.getTLAnalysis(), diagnosticData.getLOTLCountryCode());
		detailedReport.setCertificate(cqb.execute());

		return detailedReport;
	}

}

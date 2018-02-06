package eu.europa.esig.dss.validation.executor;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class CertificateProcessExecutor implements ProcessExecutor<CertificateReports> {

	private Date currentTime;
	private ValidationPolicy policy;
	private eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData jaxbDiagnosticData;
	private DiagnosticData diagnosticData;
	private String certificateId;

	@Override
	public void setCurrentTime(Date currentTime) {
		this.currentTime = currentTime;
	}

	@Override
	public Date getCurrentTime() {
		return currentTime;
	}

	@Override
	public void setDiagnosticData(eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData diagnosticData) {
		this.jaxbDiagnosticData = diagnosticData;
	}

	@Override
	public void setValidationPolicy(ValidationPolicy validationPolicy) {
		this.policy = validationPolicy;
	}

	@Override
	public ValidationPolicy getValidationPolicy() {
		return policy;
	}

	public void setCertificateId(String certificateId) {
		this.certificateId = certificateId;
	}

	@Override
	public void setValidationLevel(ValidationLevel validationLevel) {
	}

	@Override
	public CertificateReports execute() {

		assert jaxbDiagnosticData != null && policy != null && currentTime != null;

		diagnosticData = new DiagnosticData(jaxbDiagnosticData);

		DetailedReportForCertificateBuilder detailedReportBuilder = new DetailedReportForCertificateBuilder(diagnosticData, policy, currentTime, certificateId);
		DetailedReport detailedReport = detailedReportBuilder.build();

		SimpleReportForCertificateBuilder simpleReportBuilder = new SimpleReportForCertificateBuilder(diagnosticData,
				new eu.europa.esig.dss.validation.reports.DetailedReport(detailedReport), currentTime, certificateId);
		SimpleCertificateReport simpleReport = simpleReportBuilder.build();

		return new CertificateReports(jaxbDiagnosticData, detailedReport, simpleReport);
	}

}

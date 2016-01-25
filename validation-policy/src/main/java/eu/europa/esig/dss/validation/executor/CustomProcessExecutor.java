package eu.europa.esig.dss.validation.executor;

import java.util.Date;

import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class CustomProcessExecutor implements ProcessExecutor {

	private Date currentTime = new Date();
	private ValidationLevel validationLevel = ValidationLevel.ARCHIVAL_DATA;

	private eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData jaxbDiagnosticData;
	private DiagnosticData diagnosticData;

	private ValidationPolicy policy;

	@Override
	public void getCurrentTime(Date currentTime) {
		this.currentTime = currentTime;
	}

	@Override
	public void setDiagnosticData(eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData diagnosticData) {
		this.jaxbDiagnosticData = diagnosticData;
	}

	@Override
	public void setValidationPolicy(ValidationPolicy policy) {
		this.policy = policy;
	}

	@Override
	public void setValidationLevel(ValidationLevel validationLevel) {
		this.validationLevel = validationLevel;
	}

	@Override
	public Reports execute() {

		assert jaxbDiagnosticData != null && policy != null && currentTime != null && validationLevel != null;

		diagnosticData = new DiagnosticData(jaxbDiagnosticData);

		DetailedReportBuilder detailedReportBuilder = new DetailedReportBuilder(currentTime, policy, validationLevel, diagnosticData);
		DetailedReport detailedReport = detailedReportBuilder.build();

		SimpleReportBuilder simpleReportBuilder = new SimpleReportBuilder(currentTime, policy, diagnosticData, detailedReport);
		SimpleReport simpleReport = simpleReportBuilder.build();

		return new Reports(jaxbDiagnosticData, detailedReport, simpleReport);
	}

	@Override
	public Date getCurrentTime() {
		return currentTime;
	}

	@Override
	public ValidationPolicy getValidationPolicy() {
		return policy;
	}

}

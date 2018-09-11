package eu.europa.esig.dss.validation.executor;

import java.util.Date;
import java.util.Objects;

import eu.europa.esig.dss.jaxb.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;

public class CustomProcessExecutor implements ProcessExecutor<Reports> {

	private Date currentTime = new Date();
	private ValidationLevel validationLevel = ValidationLevel.ARCHIVAL_DATA;

	private eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData jaxbDiagnosticData;

	private ValidationPolicy policy;

	@Override
	public void setCurrentTime(Date currentTime) {
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

		Objects.requireNonNull(jaxbDiagnosticData, "The diagnostic data is missing");
		Objects.requireNonNull(policy, "The validation policy is missing");
		Objects.requireNonNull(currentTime, "The current time is missing");
		Objects.requireNonNull(validationLevel, "The validation level is missing");

		DiagnosticData diagnosticData = new DiagnosticData(jaxbDiagnosticData);

		DetailedReportBuilder detailedReportBuilder = new DetailedReportBuilder(currentTime, policy, validationLevel, diagnosticData);
		eu.europa.esig.dss.jaxb.detailedreport.DetailedReport jaxbDetailedReport = detailedReportBuilder.build();

		DetailedReport detailedReportWrapper = new DetailedReport(jaxbDetailedReport);

		SimpleReportBuilder simpleReportBuilder = new SimpleReportBuilder(currentTime, policy, diagnosticData, detailedReportWrapper);
		SimpleReport simpleReport = simpleReportBuilder.build();

		return new Reports(jaxbDiagnosticData, jaxbDetailedReport, simpleReport);
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

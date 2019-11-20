package eu.europa.esig.dss.validation.executor.timestamp;

import java.util.Date;
import java.util.Objects;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.simpletimestampreport.jaxb.XmlSimpleTimestampReport;
import eu.europa.esig.dss.validation.reports.TimestampReports;

public class DefaultTimestampProcessExecutor implements TimestampProcessExecutor {

	private Date currentTime;
	private ValidationPolicy policy;
	private XmlDiagnosticData jaxbDiagnosticData;
	private String timestampId;

	@Override
	public void setCurrentTime(Date currentTime) {
		this.currentTime = currentTime;
	}

	@Override
	public Date getCurrentTime() {
		return currentTime;
	}

	@Override
	public void setDiagnosticData(XmlDiagnosticData diagnosticData) {
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

	@Override
	public void setTimestampId(String timestampId) {
		this.timestampId = timestampId;
	}

	@Override
	public TimestampReports execute() {

		Objects.requireNonNull(jaxbDiagnosticData, "The diagnostic data is missing");
		Objects.requireNonNull(policy, "The validation policy is missing");
		Objects.requireNonNull(currentTime, "The current time is missing");
		Objects.requireNonNull(timestampId, "The timestamp id is missing");

		DiagnosticData diagnosticData = new DiagnosticData(jaxbDiagnosticData);

		DetailedReportForTimestampBuilder detailedReportBuilder = new DetailedReportForTimestampBuilder(diagnosticData, policy, currentTime, timestampId);
		XmlDetailedReport detailedReport = detailedReportBuilder.build();

		SimpleReportForTimestampBuilder simpleReportBuilder = new SimpleReportForTimestampBuilder(diagnosticData,
				new eu.europa.esig.dss.detailedreport.DetailedReport(detailedReport), currentTime, timestampId);
		XmlSimpleTimestampReport simpleReport = simpleReportBuilder.build();

		return new TimestampReports(jaxbDiagnosticData, detailedReport, simpleReport);
	}

}

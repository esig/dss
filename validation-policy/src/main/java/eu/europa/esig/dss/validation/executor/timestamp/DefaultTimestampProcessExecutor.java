package eu.europa.esig.dss.validation.executor.timestamp;

import java.util.Date;
import java.util.Objects;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.validation.executor.AbstractDocumentProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;

public class DefaultTimestampProcessExecutor extends AbstractDocumentProcessExecutor {

	@Override
	public Reports execute() {
		final Date currentTime = getCurrentTime();
		Objects.requireNonNull(currentTime, "The current time is missing");
		Objects.requireNonNull(jaxbDiagnosticData, "The diagnostic data is missing");
		Objects.requireNonNull(policy, "The validation policy is missing");

		DiagnosticData diagnosticData = new DiagnosticData(jaxbDiagnosticData);

		DetailedReportForTimestampBuilder detailedReportBuilder = new DetailedReportForTimestampBuilder(diagnosticData, policy, currentTime);
		XmlDetailedReport detailedReport = detailedReportBuilder.build();

		SimpleReportForTimestampBuilder simpleReportBuilder = new SimpleReportForTimestampBuilder(diagnosticData,
				new DetailedReport(detailedReport), currentTime, policy);
		XmlSimpleReport simpleReport = simpleReportBuilder.build();
		
		// TODO : etsi validation report

		return new Reports(jaxbDiagnosticData, detailedReport, simpleReport, null);
	}

}

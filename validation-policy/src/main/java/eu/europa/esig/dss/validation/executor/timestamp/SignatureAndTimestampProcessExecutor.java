package eu.europa.esig.dss.validation.executor.timestamp;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;

/**
 * This class executes a signature or/and timestamp validation process and produces
 * SimpleReport, DetailedReport and ETSI Validation report
 *
 */
public class SignatureAndTimestampProcessExecutor extends DefaultSignatureProcessExecutor {

	@Override
	protected Reports buildReports(final DiagnosticData diagnosticData, final Date validationTime) {
		// if there are timestamps and there are no signatures, execute a timestamp only validation
		if (Utils.isCollectionEmpty(diagnosticData.getSignatures()) && Utils.isCollectionNotEmpty(diagnosticData.getTimestampList())) {
			return buildTimestampOnlyReports(diagnosticData, validationTime);
		}
		return super.buildReports(diagnosticData, validationTime);
	}
	
	private Reports buildTimestampOnlyReports(final DiagnosticData diagnosticData, final Date validationTime) {
		DetailedReportForTimestampBuilder detailedReportBuilder = new DetailedReportForTimestampBuilder(diagnosticData, policy, validationTime);
		XmlDetailedReport detailedReport = detailedReportBuilder.build();

		SimpleReportForTimestampBuilder simpleReportBuilder = new SimpleReportForTimestampBuilder(diagnosticData,
				new DetailedReport(detailedReport), validationTime, policy);
		XmlSimpleReport simpleReport = simpleReportBuilder.build();
		
		// TODO : etsi validation report

		return new Reports(jaxbDiagnosticData, detailedReport, simpleReport, null);
	}

}

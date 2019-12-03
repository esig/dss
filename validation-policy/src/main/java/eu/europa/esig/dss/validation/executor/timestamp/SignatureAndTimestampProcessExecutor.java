package eu.europa.esig.dss.validation.executor.timestamp;

import java.util.Date;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.executor.signature.ETSIValidationReportBuilder;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.validationreport.jaxb.ValidationReportType;

/**
 * This class executes a signature or/and timestamp validation process and produces
 * SimpleReport, DetailedReport and ETSI Validation report
 *
 */
public class SignatureAndTimestampProcessExecutor extends DefaultSignatureProcessExecutor implements TimestampProcessExecutor {

	@Override
	protected Reports buildReports(final DiagnosticData diagnosticData, final Date validationTime) {
		// if there are timestamps and there are no signatures, execute a timestamp only validation
		if (Utils.isCollectionEmpty(diagnosticData.getSignatures()) && Utils.isCollectionNotEmpty(diagnosticData.getTimestampList())) {
			return buildTimestampOnlyReports(diagnosticData, validationTime);
		}
		return super.buildReports(diagnosticData, validationTime);
	}
	
	private Reports buildTimestampOnlyReports(final DiagnosticData diagnosticData, final Date validationTime) {
		DetailedReportForTimestampBuilder detailedReportBuilder = new DetailedReportForTimestampBuilder(getI18nProvider(), diagnosticData, policy, validationTime);
		XmlDetailedReport jaxbDetailedReport = detailedReportBuilder.build();

		DetailedReport detailedReportWrapper = new DetailedReport(jaxbDetailedReport);

		SimpleReportForTimestampBuilder simpleReportBuilder = new SimpleReportForTimestampBuilder(diagnosticData,
				new DetailedReport(jaxbDetailedReport), validationTime, policy);
		XmlSimpleReport simpleReport = simpleReportBuilder.build();

		ValidationReportType validationReport = null;
		if (enableEtsiValidationReport) {
			ETSIValidationReportBuilder etsiValidationReportBuilder = new ETSIValidationReportBuilder(getCurrentTime(), diagnosticData,
					detailedReportWrapper);
			validationReport = etsiValidationReportBuilder.build();
		}

		return new Reports(jaxbDiagnosticData, jaxbDetailedReport, simpleReport, validationReport);
	}

}

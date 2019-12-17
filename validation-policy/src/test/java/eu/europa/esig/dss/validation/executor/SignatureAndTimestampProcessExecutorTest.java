package eu.europa.esig.dss.validation.executor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.timestamp.SignatureAndTimestampProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;

public class SignatureAndTimestampProcessExecutorTest extends AbstractTestValidationExecutor {

	@Test
	public void qtsa() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/timestamp-validation/qtsa.xml"));
		assertNotNull(diagnosticData);

		SignatureAndTimestampProcessExecutor executor = new SignatureAndTimestampProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();
		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.QTSA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));

		checkReports(reports);
	}

	@Test
	public void tsa() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/timestamp-validation/tsa.xml"));
		assertNotNull(diagnosticData);

		SignatureAndTimestampProcessExecutor executor = new SignatureAndTimestampProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.TSA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));

		checkReports(reports);
	}

	@Test
	public void na() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/timestamp-validation/na.xml"));
		assertNotNull(diagnosticData);

		SignatureAndTimestampProcessExecutor executor = new SignatureAndTimestampProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.NA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));

		XmlDetailedReport detailedReportJaxb = reports.getDetailedReportJaxb();
		assertEquals(0, detailedReportJaxb.getSignatures().size());
		assertEquals(1, detailedReportJaxb.getTimestamps().size());

		checkReports(reports);
	}

	@Test
	public void sigAndTst() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/timestamp-validation/sig-and-tst.xml"));
		assertNotNull(diagnosticData);

		SignatureAndTimestampProcessExecutor executor = new SignatureAndTimestampProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.NA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));

		XmlDetailedReport detailedReportJaxb = reports.getDetailedReportJaxb();
		assertEquals(2, detailedReportJaxb.getSignatures().size());
		assertEquals(2, detailedReportJaxb.getTimestamps().size());

		checkReports(reports);
	}

}

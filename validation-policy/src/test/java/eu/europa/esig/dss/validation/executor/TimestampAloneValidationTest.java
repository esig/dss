package eu.europa.esig.dss.validation.executor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.TimestampQualification;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;

public class TimestampAloneValidationTest extends AbstractTestValidationExecutor {

	@Test
	public void qtsa() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/timestamp-validation/qtsa.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
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

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
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

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.NA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(0, detailedReport.getSignatures().size());
		assertEquals(1, detailedReport.getIndependentTimestamps().size());

		checkReports(reports);
	}

	@Test
	public void sigAndTst() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/timestamp-validation/sig-and-tst.xml"));
		assertNotNull(diagnosticData);

		DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		executor.setValidationPolicy(loadDefaultPolicy());
		Reports reports = executor.execute();

		// reports.print();

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(TimestampQualification.NA, simpleReport.getTimestampQualification(simpleReport.getFirstTimestampId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(2, detailedReport.getSignatures().size());
		assertEquals(2, detailedReport.getIndependentTimestamps().size());

		checkReports(reports);
	}

}

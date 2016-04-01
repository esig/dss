package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;
import java.io.InputStream;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.collections.CollectionUtils;
import org.junit.Test;

import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class CustomProcessExecutorTest {

	@Test
	public void test() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/diagnosticData.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class);
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
		Date currentTime = sdf.parse("03/03/2016 09:25:00");
		executor.setCurrentTime(currentTime);

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.VALID, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void testPsvOutOfBoundsNoPoe() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/diagnosticDataPSV.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class);
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
		Date currentTime = sdf.parse("03/03/2016 09:25:00");
		executor.setCurrentTime(currentTime);

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.INDETERMINATE, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getArchiveDataValidationSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void testPsv() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/DSS-841-diagnosticdata.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class);
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
		Date currentTime = sdf.parse("01/04/2016 12:00:00");
		executor.setCurrentTime(currentTime);

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.VALID, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NO_POE, detailedReport.getBasicValidationSubIndication(simpleReport.getFirstSignatureId()));

		assertEquals(Indication.VALID, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void testLTA() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/diagnosticDataLTA.xml");
		DiagnosticData diagnosticData = getJAXBObjectFromString(fis, DiagnosticData.class);
		assertNotNull(diagnosticData);

		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy());
		SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
		Date currentTime = sdf.parse("03/03/2016 11:21:00");
		executor.setCurrentTime(currentTime);

		Reports reports = executor.execute();
		assertNotNull(reports);

		SimpleReport simpleReport = reports.getSimpleReport();
		assertEquals(Indication.VALID, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

		DetailedReport detailedReport = reports.getDetailedReport();
		assertEquals(Indication.VALID, detailedReport.getArchiveDataValidationIndication(simpleReport.getFirstSignatureId()));

		assertEquals(2, CollectionUtils.size(detailedReport.getTimestampIds()));
	}

	private EtsiValidationPolicy loadPolicy() throws Exception {
		FileInputStream policyFis = new FileInputStream("src/main/resources/policy/constraint.xml");
		ConstraintsParameters policyJaxB = getJAXBObjectFromString(policyFis, ConstraintsParameters.class);
		assertNotNull(policyJaxB);
		return new EtsiValidationPolicy(policyJaxB);
	}

	@SuppressWarnings("unchecked")
	private <T extends Object> T getJAXBObjectFromString(InputStream is, Class<T> clazz) throws Exception {
		JAXBContext context = JAXBContext.newInstance(clazz.getPackage().getName());
		Unmarshaller unmarshaller = context.createUnmarshaller();
		return (T) unmarshaller.unmarshal(is);
	}

}

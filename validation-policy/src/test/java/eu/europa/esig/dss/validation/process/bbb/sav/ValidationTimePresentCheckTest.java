package eu.europa.esig.dss.validation.process.bbb.sav;

import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.validation.executor.AbstractValidationExecutorTest;
import eu.europa.esig.dss.validation.executor.CustomProcessExecutor;
import eu.europa.esig.dss.validation.policy.XmlUtils;
import eu.europa.esig.dss.validation.reports.DetailedReport;
import eu.europa.esig.dss.validation.reports.Reports;

public class ValidationTimePresentCheckTest extends AbstractValidationExecutorTest {
	
	@Test
	public void test() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/universign.xml");
		DiagnosticData diagnosticData = XmlUtils.getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");
		assertNotNull(diagnosticData);
		
		CustomProcessExecutor executor = new CustomProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setValidationPolicy(loadPolicy("src/test/resources/policy/default-only-constraint-policy.xml"));
		executor.setCurrentTime(diagnosticData.getValidationDate());
		
		Reports reports = executor.execute();
		DetailedReport detailedReport = reports.getDetailedReport();
		
		XmlSAV sav = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId()).getSAV();
		assertNotNull(sav.getValidationTime());
	}

}

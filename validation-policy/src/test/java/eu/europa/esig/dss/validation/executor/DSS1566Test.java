package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.io.FileInputStream;
import java.util.Date;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.diagnostic.DiagnosticData;
import eu.europa.esig.dss.validation.policy.XmlUtils;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.reports.CertificateReports;
import eu.europa.esig.dss.validation.reports.SimpleCertificateReport;

public class DSS1566Test extends AbstractValidationExecutorTest {
	
	@Test
	public void test() throws Exception {
		FileInputStream fis = new FileInputStream("src/test/resources/dss1566-diagnostic.xml");
		DiagnosticData diagnosticData = XmlUtils.getJAXBObjectFromString(fis, DiagnosticData.class, "/xsd/DiagnosticData.xsd");

		CertificateProcessExecutor executor = new CertificateProcessExecutor();
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setDiagnosticData(diagnosticData);
		executor.setCertificateId("D04D16660A6BA5FDD2C3A519DAD8877B64D1D2C56BF91316208A0AE2FB76D368");
		executor.setCurrentTime(new Date());
		
		CertificateReports reports = executor.execute();
		assertNotNull(reports);
		SimpleCertificateReport simpleReport = reports.getSimpleReport();
		assertNotNull(simpleReport);
		List<String> certIds = simpleReport.getCertificateIds();
		assertNotEquals(0, certIds);
		for (String certId : certIds) {
			Indication indication = simpleReport.getCertificateIndication(certId);
			assertNotNull(indication);
		}
	}

}

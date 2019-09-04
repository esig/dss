package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.util.Date;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.validation.reports.CertificateReports;

public class DSS1566Test extends AbstractTestValidationExecutor {
	
	@Test
	public void test() throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/dss1566-diagnostic.xml"));

		DefaultCertificateProcessExecutor executor = new DefaultCertificateProcessExecutor();
		executor.setValidationPolicy(loadDefaultPolicy());
		executor.setDiagnosticData(diagnosticData);
		executor.setCertificateId("C-D04D16660A6BA5FDD2C3A519DAD8877B64D1D2C56BF91316208A0AE2FB76D368");
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
			if (!Indication.PASSED.equals(indication)) {
				SubIndication subIndication = simpleReport.getCertificateSubIndication(certId);
				assertNotNull(subIndication);
			}
		}
	}

}

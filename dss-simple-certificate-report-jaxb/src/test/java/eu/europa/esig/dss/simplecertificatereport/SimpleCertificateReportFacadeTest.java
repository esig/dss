package eu.europa.esig.dss.simplecertificatereport;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;

import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;

public class SimpleCertificateReportFacadeTest {

	@Test
	public void test() throws Exception {
		
		SimpleCertificateReportFacade facade = SimpleCertificateReportFacade.newFacade();

		XmlSimpleCertificateReport simpleCertificateReport = facade.unmarshall(new File("src/test/resources/simple-cert-report.xml"));
		assertNotNull(simpleCertificateReport);

		String htmlReport = facade.generateHtmlReport(simpleCertificateReport);
		assertNotNull(htmlReport);
	}

	@Test
	public void test2() throws Exception {

		SimpleCertificateReportFacade facade = SimpleCertificateReportFacade.newFacade();

		XmlSimpleCertificateReport simpleCertificateReport = facade.unmarshall(new File("src/test/resources/simple-cert-report2.xml"));
		assertNotNull(simpleCertificateReport);

		String htmlReport = facade.generateHtmlReport(simpleCertificateReport);
		assertNotNull(htmlReport);
	}

}

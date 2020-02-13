package eu.europa.esig.dss.simplecertificatereport;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.FileOutputStream;

import javax.xml.transform.Result;
import javax.xml.transform.sax.SAXResult;

import org.apache.fop.apps.FOUserAgent;
import org.apache.fop.apps.Fop;
import org.apache.fop.apps.FopFactory;
import org.apache.fop.apps.FopFactoryBuilder;
import org.apache.fop.apps.MimeConstants;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.simplecertificatereport.jaxb.XmlSimpleCertificateReport;

public class PDFGenerationTest {

	private static FopFactory fopFactory;
	private static FOUserAgent foUserAgent;

	@BeforeAll
	public static void init() throws Exception {
		FopFactoryBuilder builder = new FopFactoryBuilder(new File(".").toURI());
		builder.setAccessibility(true);

		fopFactory = builder.build();

		foUserAgent = fopFactory.newFOUserAgent();
		foUserAgent.setCreator("DSS Webapp");
		foUserAgent.setAccessibility(true);
	}

	@Test
	public void generateSimpleCertificateReport() throws Exception {
		createAndValidate("simple-cert-report.xml");
	}

	@Test
	public void generateSimpleCertificateReport2() throws Exception {
		createAndValidate("simple-cert-report2.xml");
	}
	
	private void createAndValidate(String filename) throws Exception {
		SimpleCertificateReportFacade facade = SimpleCertificateReportFacade.newFacade();

		File file = new File("src/test/resources/" + filename);
		XmlSimpleCertificateReport simpleReport = facade.unmarshall(file);

		try (FileOutputStream fos = new FileOutputStream("target/report.pdf")) {
			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, fos);
			Result result = new SAXResult(fop.getDefaultHandler());
			facade.generatePdfReport(simpleReport, result);
		}
		
		File pdfReport = new File("target/report.pdf");
		assertTrue(pdfReport.exists());
		assertTrue(pdfReport.delete(), "Cannot delete PDF document (IO error)");
		assertFalse(pdfReport.exists());
	}

}

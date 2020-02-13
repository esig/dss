package eu.europa.esig.dss.detailedreport;

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

import eu.europa.esig.dss.detailedreport.jaxb.XmlDetailedReport;

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
	public void generateDetailedReport() throws Exception {
		createAndValidate("dr1.xml");
	}

	@Test
	public void generateDetailedReport2() throws Exception {
		createAndValidate("dr2.xml");
	}

	@Test
	public void generateTstDetailedReport() throws Exception {
		createAndValidate("dr-tst.xml");
	}

	@Test
	public void generateCertificateDetailedReport() throws Exception {
		createAndValidate("dr-cert.xml");
	}

	@Test
	public void generateSigAndTstDetailedReport() throws Exception {
		createAndValidate("dr-sig-and-tst.xml");
	}
	
	private void createAndValidate(String filename) throws Exception {
		DetailedReportFacade facade = DetailedReportFacade.newFacade();

		File file = new File("src/test/resources/" + filename);
		XmlDetailedReport detailedReport = facade.unmarshall(file);

		try (FileOutputStream fos = new FileOutputStream("target/report.pdf")) {

			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, fos);
			Result result = new SAXResult(fop.getDefaultHandler());
			facade.generatePdfReport(detailedReport, result);
		}
		
		File pdfReport = new File("target/report.pdf");
		assertTrue(pdfReport.exists());
		assertTrue(pdfReport.delete(), "Cannot delete PDF document (IO error)");
		assertFalse(pdfReport.exists());
		
	}
	

}

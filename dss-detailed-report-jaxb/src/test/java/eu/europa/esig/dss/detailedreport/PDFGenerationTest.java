package eu.europa.esig.dss.detailedreport;

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
		DetailedReportFacade facade = DetailedReportFacade.newFacade();

		File file = new File("src/test/resources/dr1.xml");
		XmlDetailedReport detailedReport = facade.unmarshall(file);

		try (FileOutputStream fos = new FileOutputStream("target/dr1.pdf")) {

			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, fos);
			Result result = new SAXResult(fop.getDefaultHandler());
			facade.generatePdfReport(detailedReport, result);
		}
	}

	@Test
	public void generateDetailedReport2() throws Exception {
		DetailedReportFacade facade = DetailedReportFacade.newFacade();

		File file = new File("src/test/resources/dr2.xml");
		XmlDetailedReport detailedReport = facade.unmarshall(file);

		try (FileOutputStream fos = new FileOutputStream("target/dr2.pdf")) {

			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, fos);
			Result result = new SAXResult(fop.getDefaultHandler());
			facade.generatePdfReport(detailedReport, result);
		}
	}

	@Test
	public void generateTstDetailedReport() throws Exception {
		DetailedReportFacade facade = DetailedReportFacade.newFacade();

		File file = new File("src/test/resources/dr-tst.xml");
		XmlDetailedReport detailedReport = facade.unmarshall(file);

		try (FileOutputStream fos = new FileOutputStream("target/dr-tst.pdf")) {

			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, fos);
			Result result = new SAXResult(fop.getDefaultHandler());
			facade.generatePdfReport(detailedReport, result);
		}
	}

	@Test
	public void generateCertificateDetailedReport() throws Exception {
		DetailedReportFacade facade = DetailedReportFacade.newFacade();

		File file = new File("src/test/resources/dr-cert.xml");
		XmlDetailedReport detailedReport = facade.unmarshall(file);

		try (FileOutputStream fos = new FileOutputStream("target/dr-cert.pdf")) {

			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, fos);
			Result result = new SAXResult(fop.getDefaultHandler());
			facade.generatePdfReport(detailedReport, result);
		}
	}

	@Test
	public void generateSigAndTstDetailedReport() throws Exception {
		DetailedReportFacade facade = DetailedReportFacade.newFacade();

		File file = new File("src/test/resources/dr-sig-and-tst.xml");
		XmlDetailedReport detailedReport = facade.unmarshall(file);

		try (FileOutputStream fos = new FileOutputStream("target/dr-sig-and-tst.pdf")) {

			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, fos);
			Result result = new SAXResult(fop.getDefaultHandler());
			facade.generatePdfReport(detailedReport, result);
		}
	}

}

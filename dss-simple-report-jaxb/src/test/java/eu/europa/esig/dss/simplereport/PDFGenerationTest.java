package eu.europa.esig.dss.simplereport;

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

import eu.europa.esig.dss.simplereport.jaxb.XmlSimpleReport;

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
		SimpleReportFacade facade = SimpleReportFacade.newFacade();

		File file = new File("src/test/resources/sr1.xml");
		XmlSimpleReport simpleReport = facade.unmarshall(file);

		try (FileOutputStream fos = new FileOutputStream("target/sr1.pdf")) {

			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, fos);
			Result result = new SAXResult(fop.getDefaultHandler());
			facade.generatePdfReport(simpleReport, result);
		}
	}

	@Test
	public void generateDetailedReport2() throws Exception {
		SimpleReportFacade facade = SimpleReportFacade.newFacade();

		File file = new File("src/test/resources/sr2.xml");
		XmlSimpleReport simpleReport = facade.unmarshall(file);

		try (FileOutputStream fos = new FileOutputStream("target/sr2.pdf")) {

			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, fos);
			Result result = new SAXResult(fop.getDefaultHandler());
			facade.generatePdfReport(simpleReport, result);
		}
	}

	@Test
	public void generateSigAndTstDetailedReport() throws Exception {
		SimpleReportFacade facade = SimpleReportFacade.newFacade();

		File file = new File("src/test/resources/sr-sig-and-tst.xml");
		XmlSimpleReport simpleReport = facade.unmarshall(file);

		try (FileOutputStream fos = new FileOutputStream("target/sr-sig-and-tst.pdf")) {

			Fop fop = fopFactory.newFop(MimeConstants.MIME_PDF, foUserAgent, fos);
			Result result = new SAXResult(fop.getDefaultHandler());
			facade.generatePdfReport(simpleReport, result);
		}
	}

}

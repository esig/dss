package eu.europa.esig.dss.web.service;

import static org.junit.Assert.assertNotNull;

import java.io.FileOutputStream;
import java.io.InputStream;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.w3c.dom.Document;

import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.validation.report.DetailedReport;
import eu.europa.esig.dss.validation.report.SimpleReport;

@ContextConfiguration("/spring/applicationContext.xml")
@RunWith(SpringJUnit4ClassRunner.class)
public class FOPServiceTest {

	@Autowired
	private FOPService service;

	@Test
	public void generateSimpleReportFiveSignatures() throws Exception {
		InputStream is = FOPServiceTest.class.getResourceAsStream("/simple-report-5-signatures.xml");

		Document document = DSSXMLUtils.buildDOM(is);
		SimpleReport report = new SimpleReport(document);
		assertNotNull(report);

		FileOutputStream fos = new FileOutputStream("target/simpleReportFiveSignature.pdf");
		service.generateSimpleReport(report, fos);
	}

	@Test
	public void generateDetailedReportFiveSignatures() throws Exception {
		InputStream is = FOPServiceTest.class.getResourceAsStream("/validation-report-5-signatures.xml");

		Document document = DSSXMLUtils.buildDOM(is);
		DetailedReport report = new DetailedReport(document);
		assertNotNull(report);

		FileOutputStream fos = new FileOutputStream("target/detailedReportFiveSignature.pdf");
		service.generateDetailedReport(report, fos);
	}

}

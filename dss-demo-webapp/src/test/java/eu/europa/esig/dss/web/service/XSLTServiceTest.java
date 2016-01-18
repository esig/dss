package eu.europa.esig.dss.web.service;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@ContextConfiguration("/spring/applicationContext.xml")
@RunWith(SpringJUnit4ClassRunner.class)
public class XSLTServiceTest {

	private static final Logger logger = LoggerFactory.getLogger(XSLTServiceTest.class);

	@Autowired
	private XSLTService service;

	@Test
	public void generateSimpleReportFiveSignatures() throws Exception {
		// TODO
		// InputStream is = XSLTServiceTest.class
		// .getResourceAsStream("/simple-report-5-signatures.xml");
		//
		// Document document = DSSXMLUtils.buildDOM(is);
		// assertNotNull(document);
		//
		// String htmlSimpleReport = service.generateSimpleReport(document);
		// assertTrue(StringUtils.isNotEmpty(htmlSimpleReport));
		// logger.info("Simple report html : " + htmlSimpleReport);
	}

	@Test
	public void generateDetailedReportFiveSignatures() throws Exception {
		// TODO
		// InputStream is = XSLTServiceTest.class
		// .getResourceAsStream("/validation-report-5-signatures.xml");
		//
		// Document document = DSSXMLUtils.buildDOM(is);
		// DetailedReport report = new DetailedReport(document);
		// assertNotNull(report);
		//
		// String htmlDetailedReport = service.generateDetailedReport(report);
		// assertTrue(StringUtils.isNotEmpty(htmlDetailedReport));
		// logger.info("Detailed report html : " + htmlDetailedReport);

	}

}

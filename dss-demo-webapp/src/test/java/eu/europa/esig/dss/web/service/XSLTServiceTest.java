package eu.europa.esig.dss.web.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;

import org.apache.commons.lang.StringUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.w3c.dom.Document;

import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.validation.report.DetailedReport;
import eu.europa.esig.dss.validation.report.SimpleReport;

@ContextConfiguration("/spring/applicationContext.xml")
@RunWith(SpringJUnit4ClassRunner.class)
public class XSLTServiceTest {

	private static final Logger logger = LoggerFactory
			.getLogger(XSLTServiceTest.class);

	@Autowired
	private XSLTService service;

	@Test
	public void generateSimpleReportFiveSignatures() throws Exception {
		InputStream is = XSLTServiceTest.class
				.getResourceAsStream("/simple-report-5-signatures.xml");

		Document document = DSSXMLUtils.buildDOM(is);
		SimpleReport report = new SimpleReport(document);
		assertNotNull(report);

		String htmlSimpleReport = service.generateSimpleReport(report);
		assertTrue(StringUtils.isNotEmpty(htmlSimpleReport));
		logger.info("Simple report html : " + htmlSimpleReport);
	}

	@Test
	public void generateDetailedReportFiveSignatures() throws Exception {
		InputStream is = XSLTServiceTest.class
				.getResourceAsStream("/validation-report-5-signatures.xml");

		Document document = DSSXMLUtils.buildDOM(is);
		DetailedReport report = new DetailedReport(document);
		assertNotNull(report);

		String htmlDetailedReport = service.generateDetailedReport(report);
		assertTrue(StringUtils.isNotEmpty(htmlDetailedReport));
		logger.info("Detailed report html : " + htmlDetailedReport);

	}

}

package eu.europa.esig.dss.web.service;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.lang.StringUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.jaxb.simplereport.SimpleReport;

@ContextConfiguration("/spring/applicationContext.xml")
@RunWith(SpringJUnit4ClassRunner.class)
public class XSLTServiceTest {

	private static final Logger logger = LoggerFactory.getLogger(XSLTServiceTest.class);

	@Autowired
	private XSLTService service;

	@Test
	public void generateSimpleReport() throws Exception {
		JAXBContext context = JAXBContext.newInstance(SimpleReport.class.getPackage().getName());
		Unmarshaller unmarshaller = context.createUnmarshaller();
		Marshaller marshaller = context.createMarshaller();

		SimpleReport simpleReport = (SimpleReport) unmarshaller.unmarshal(new File("src/test/resources/simpleReport.xml"));
		assertNotNull(simpleReport);

		StringWriter writer = new StringWriter();
		marshaller.marshal(simpleReport, writer);

		String htmlSimpleReport = service.generateSimpleReport(writer.toString());
		assertTrue(StringUtils.isNotEmpty(htmlSimpleReport));
		logger.debug("Simple report html : " + htmlSimpleReport);
	}

	@Test
	public void generateDetailedReportFiveSignatures() throws Exception {
		JAXBContext context = JAXBContext.newInstance(DetailedReport.class.getPackage().getName());
		Unmarshaller unmarshaller = context.createUnmarshaller();
		Marshaller marshaller = context.createMarshaller();

		DetailedReport detailedReport = (DetailedReport) unmarshaller.unmarshal(new File("src/test/resources/detailedReport.xml"));
		assertNotNull(detailedReport);

		StringWriter writer = new StringWriter();
		marshaller.marshal(detailedReport, writer);

		String htmlDetailedReport = service.generateDetailedReport(writer.toString());
		assertTrue(StringUtils.isNotEmpty(htmlDetailedReport));
		logger.debug("Detailed report html : " + htmlDetailedReport);

	}

}

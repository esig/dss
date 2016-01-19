package eu.europa.esig.dss.web.service;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.w3c.dom.Document;

import eu.europa.esig.dss.DSSXMLUtils;
import eu.europa.esig.dss.jaxb.detailedreport.DetailedReport;
import eu.europa.esig.dss.validation.report.Reports;

@ContextConfiguration("/spring/applicationContext.xml")
@RunWith(SpringJUnit4ClassRunner.class)
public class FOPServiceTest {

	@Autowired
	private FOPService service;

	@Test
	public void generateSimpleReportFiveSignatures() throws Exception {
		// TODO
		// InputStream is =
		// FOPServiceTest.class.getResourceAsStream("/simple-report-5-signatures.xml");
		//
		// Document document = DSSXMLUtils.buildDOM(is);
		// assertNotNull(document);
		//
		// FileOutputStream fos = new
		// FileOutputStream("target/simpleReportFiveSignature.pdf");
		// service.generateSimpleReport(document, fos);
	}

	@Test
	public void generateDetailedReport() throws Exception {
		JAXBContext context = JAXBContext
				.newInstance(DetailedReport.class.getPackage().getName());
		Unmarshaller unmarshaller = context.createUnmarshaller();
		Marshaller marshaller = context.createMarshaller();

		DetailedReport detailedReport = (DetailedReport) unmarshaller.unmarshal(new File("src/test/resources/detailedReport.xml"));
		assertNotNull(detailedReport);
		
		StringWriter writer = new StringWriter();
		marshaller.marshal(detailedReport, writer);

		FileOutputStream fos = new FileOutputStream("target/detailedReport.pdf");
		service.generateDetailedReport(writer.toString(), fos);
	}

}

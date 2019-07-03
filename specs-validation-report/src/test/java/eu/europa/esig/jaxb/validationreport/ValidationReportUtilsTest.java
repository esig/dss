package eu.europa.esig.jaxb.validationreport;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import javax.xml.bind.JAXBException;

import org.junit.Test;
import org.xml.sax.SAXException;

public class ValidationReportUtilsTest {

	@Test
	public void getJAXBContext() throws JAXBException {
		assertNotNull(ValidationReportUtils.getJAXBContext());
		// cached
		assertNotNull(ValidationReportUtils.getJAXBContext());
	}

	@Test
	public void getSchema() throws IOException, SAXException {
		assertNotNull(ValidationReportUtils.getSchema());
		// cached
		assertNotNull(ValidationReportUtils.getSchema());
	}

}

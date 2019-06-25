package eu.europa.esig.jaxb.validationreport;

import static org.junit.Assert.assertNotNull;

import javax.xml.bind.JAXBContext;

import org.junit.Test;

public class ValidationReportUtilsTest {

	@Test
	public void getJAXBContext() {
		JAXBContext jaxbContext = ValidationReportUtils.getJAXBContext();
		assertNotNull(jaxbContext);
		assertNotNull(ValidationReportUtils.getJAXBContext());
	}

	@Test
	public void getSchema() {
		assertNotNull(ValidationReportUtils.getSchema());
		// cached
		assertNotNull(ValidationReportUtils.getSchema());
	}

}

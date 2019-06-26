package eu.europa.esig.jaxb.validationreport;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.FileInputStream;
import java.io.FileNotFoundException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.junit.Test;

public class ValidationReportUtilsTest {

	@Test
	@SuppressWarnings("unchecked")
	public void getJAXBContext() throws JAXBException, FileNotFoundException {
		JAXBContext jaxbContext = ValidationReportUtils.getJAXBContext();
		assertNotNull(jaxbContext);
		assertNotNull(ValidationReportUtils.getJAXBContext());

		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		JAXBElement<ValidationReportType> unmarshal = (JAXBElement<ValidationReportType>) unmarshaller
				.unmarshal(new FileInputStream("src/test/resources/vr.xml"));
		assertNotNull(unmarshal);
		ValidationReportType validationReportType = unmarshal.getValue();
		assertNotNull(validationReportType);
		assertFalse(validationReportType.getSignatureValidationObjects().getValidationObject().isEmpty());
		assertFalse(validationReportType.getSignatureValidationReport().isEmpty());
		assertNull(validationReportType.getSignature());
	}

	@Test
	public void getSchema() {
		assertNotNull(ValidationReportUtils.getSchema());
		// cached
		assertNotNull(ValidationReportUtils.getSchema());
	}

}

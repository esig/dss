package eu.europa.esig.jaxb.validationreport;

import static org.junit.Assert.assertNotNull;

import java.io.File;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.junit.Test;

public class MarshallTest {

	@Test
	@SuppressWarnings("unchecked")
	public void unmarshall() throws JAXBException {
		JAXBContext jaxbContext = ValidationReportUtils.getJAXBContext();
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		JAXBElement<ValidationReportType> unmarshal = (JAXBElement<ValidationReportType>) unmarshaller.unmarshal(new File("src/test/resources/Sample-vr2.xml"));
		assertNotNull(unmarshal);
		ValidationReportType validationReportType = unmarshal.getValue();
		assertNotNull(validationReportType);
	}

}

package eu.europa.esig.jaxb.validationreport;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.FileInputStream;
import java.io.IOException;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

import org.junit.Test;
import org.xml.sax.SAXException;

public class ValidationReportFacadeTest {

	@Test
	public void unmarshallAndMarshall() throws IOException, JAXBException, XMLStreamException, SAXException {
		try (FileInputStream fis = new FileInputStream("src/test/resources/vr.xml")) {
			ValidationReportFacade facade = ValidationReportFacade.newFacade();
			ValidationReportType validationReportType = facade.unmarshall(fis);

			assertNotNull(validationReportType);
			assertFalse(validationReportType.getSignatureValidationObjects().getValidationObject().isEmpty());
			assertFalse(validationReportType.getSignatureValidationReport().isEmpty());
			assertNull(validationReportType.getSignature());

			String marshall = facade.marshall(validationReportType, true);
			assertNotNull(marshall);
		}
	}

}

package eu.europa.esig.jaxb.validationreport;

import java.io.IOException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.AbstractJaxbFacade;

public class ValidationReportFacade extends AbstractJaxbFacade<ValidationReportType> {

	public static ValidationReportFacade newFacade() {
		return new ValidationReportFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return ValidationReportUtils.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return ValidationReportUtils.getSchema();
	}

	@Override
	protected JAXBElement<ValidationReportType> wrap(ValidationReportType jaxbObject) {
		return ValidationReportUtils.OBJECT_FACTORY.createValidationReport(jaxbObject);
	}

}

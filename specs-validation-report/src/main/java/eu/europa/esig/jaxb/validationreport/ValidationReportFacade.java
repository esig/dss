package eu.europa.esig.jaxb.validationreport;

import java.io.IOException;
import java.io.StringWriter;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.MarshallerBuilder;

public class ValidationReportFacade {

	public static ValidationReportFacade newFacade() {
		return new ValidationReportFacade();
	}

	public String marshall(ValidationReportType validationReport, boolean validate) throws JAXBException, IOException, SAXException {
		MarshallerBuilder marshallerBuilder = new MarshallerBuilder(ValidationReportUtils.getJAXBContext(), ValidationReportUtils.getSchema());
		marshallerBuilder.setIndent(true);
		marshallerBuilder.setValidate(validate);
		Marshaller marshaller = marshallerBuilder.buildMarshaller();

		StringWriter writer = new StringWriter();
		marshaller.marshal(ValidationReportUtils.OBJECT_FACTORY.createValidationReport(validationReport), writer);
		return writer.toString();
	}

}

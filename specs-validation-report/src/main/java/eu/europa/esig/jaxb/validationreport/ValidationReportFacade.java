package eu.europa.esig.jaxb.validationreport;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.MarshallerBuilder;

public class ValidationReportFacade {

	public static ValidationReportFacade newFacade() {
		return new ValidationReportFacade();
	}

	public String marshall(ValidationReportType validationReport, boolean validate) throws JAXBException, IOException, SAXException {
		Marshaller marshaller = getMarshaller(validate);

		try (StringWriter writer = new StringWriter()) {
			marshaller.marshal(ValidationReportUtils.OBJECT_FACTORY.createValidationReport(validationReport), writer);
			return writer.toString();
		}
	}

	public void marshall(ValidationReportType validationReport, OutputStream os, boolean validate) throws JAXBException, IOException, SAXException {
		Marshaller marshaller = getMarshaller(validate);

		marshaller.marshal(ValidationReportUtils.OBJECT_FACTORY.createValidationReport(validationReport), os);
	}

	private Marshaller getMarshaller(boolean validate) throws JAXBException, IOException, SAXException {
		MarshallerBuilder marshallerBuilder = new MarshallerBuilder(ValidationReportUtils.getJAXBContext(), ValidationReportUtils.getSchema());
		marshallerBuilder.setIndent(true);
		marshallerBuilder.setValidate(validate);
		return marshallerBuilder.buildMarshaller();
	}

	@SuppressWarnings("unchecked")
	public ValidationReportType unmarshall(InputStream inputStream) throws JAXBException, XMLStreamException {
		JAXBContext jaxbContext = ValidationReportUtils.getJAXBContext();
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		JAXBElement<ValidationReportType> unmarshal = (JAXBElement<ValidationReportType>) unmarshaller.unmarshal(avoidXXE(new StreamSource(inputStream)));
		return unmarshal.getValue();
	}

	private XMLStreamReader avoidXXE(Source source) throws XMLStreamException {
		XMLInputFactory xif = XMLInputFactory.newFactory();
		xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
		xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
		return xif.createXMLStreamReader(source);
	}

}

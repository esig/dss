package eu.europa.esig.dss.jaxb.simplereport;

import java.io.IOException;
import java.io.StringWriter;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.MarshallerBuilder;

public class SimpleReportFacade {

	public static SimpleReportFacade newFacade() {
		return new SimpleReportFacade();
	}

	public String marshall(XmlSimpleReport simpleReport, boolean validate) throws JAXBException, IOException, SAXException {
		MarshallerBuilder marshallerBuilder = new MarshallerBuilder(SimpleReportXmlDefiner.getJAXBContext(), SimpleReportXmlDefiner.getSchema());
		marshallerBuilder.setIndent(true);
		marshallerBuilder.setValidate(validate);
		Marshaller marshaller = marshallerBuilder.buildMarshaller();

		StringWriter writer = new StringWriter();
		marshaller.marshal(SimpleReportXmlDefiner.OBJECT_FACTORY.createSimpleReport(simpleReport), writer);
		return writer.toString();
	}

}

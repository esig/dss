package eu.europa.esig.dss.jaxb.simplecertificatereport;

import java.io.IOException;
import java.io.StringWriter;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.MarshallerBuilder;

public class SimpleCertificateReportFacade {

	public static SimpleCertificateReportFacade newFacade() {
		return new SimpleCertificateReportFacade();
	}

	public String marshall(XmlSimpleCertificateReport simpleReport, boolean validate) throws JAXBException, IOException, SAXException {
		MarshallerBuilder marshallerBuilder = new MarshallerBuilder(SimpleCertificateReportXmlDefiner.getJAXBContext(),
				SimpleCertificateReportXmlDefiner.getSchema());
		marshallerBuilder.setIndent(true);
		marshallerBuilder.setValidate(validate);
		Marshaller marshaller = marshallerBuilder.buildMarshaller();

		StringWriter writer = new StringWriter();
		marshaller.marshal(SimpleCertificateReportXmlDefiner.OBJECT_FACTORY.createSimpleCertificateReport(simpleReport), writer);
		return writer.toString();
	}

}

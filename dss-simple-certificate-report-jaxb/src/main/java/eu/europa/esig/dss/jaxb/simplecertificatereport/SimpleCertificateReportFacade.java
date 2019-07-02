package eu.europa.esig.dss.jaxb.simplecertificatereport;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.util.JAXBSource;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

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

		try (StringWriter writer = new StringWriter()) {
			marshaller.marshal(SimpleCertificateReportXmlDefiner.OBJECT_FACTORY.createSimpleCertificateReport(simpleReport), writer);
			return writer.toString();
		}
	}

	public String generateHtmlReport(XmlSimpleCertificateReport simpleCertificateReport) throws IOException, TransformerException, JAXBException {
		try (StringWriter stringWriter = new StringWriter()) {
			Transformer transformer = SimpleCertificateReportXmlDefiner.getHtmlTemplates().newTransformer();
			transformer.transform(
					new JAXBSource(SimpleCertificateReportXmlDefiner.getJAXBContext(),
							SimpleCertificateReportXmlDefiner.OBJECT_FACTORY.createSimpleCertificateReport(simpleCertificateReport)),
					new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public String generateHtmlReport(String marshalledSimpleCertificateReport) throws IOException, TransformerException {
		try (StringWriter stringWriter = new StringWriter()) {
			Transformer transformer = SimpleCertificateReportXmlDefiner.getHtmlTemplates().newTransformer();
			transformer.transform(new StreamSource(new StringReader(marshalledSimpleCertificateReport)), new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

}

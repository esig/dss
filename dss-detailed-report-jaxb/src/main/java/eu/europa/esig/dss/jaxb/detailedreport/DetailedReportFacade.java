package eu.europa.esig.dss.jaxb.detailedreport;

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

public class DetailedReportFacade {

	public static DetailedReportFacade newFacade() {
		return new DetailedReportFacade();
	}

	public String marshall(XmlDetailedReport detailedReport, boolean validate) throws JAXBException, IOException, SAXException {
		MarshallerBuilder marshallerBuilder = new MarshallerBuilder(DetailedReportXmlDefiner.getJAXBContext(), DetailedReportXmlDefiner.getSchema());
		marshallerBuilder.setIndent(true);
		marshallerBuilder.setValidate(validate);
		Marshaller marshaller = marshallerBuilder.buildMarshaller();

		try (StringWriter writer = new StringWriter()) {
			marshaller.marshal(DetailedReportXmlDefiner.OBJECT_FACTORY.createDetailedReport(detailedReport), writer);
			return writer.toString();
		}
	}

	public String generateHtmlReport(XmlDetailedReport detailedReport) throws IOException, TransformerException, JAXBException {
		try (StringWriter stringWriter = new StringWriter()) {
			Transformer transformer = DetailedReportXmlDefiner.getHtmlTemplates().newTransformer();
			transformer.transform(
					new JAXBSource(DetailedReportXmlDefiner.getJAXBContext(), DetailedReportXmlDefiner.OBJECT_FACTORY.createDetailedReport(detailedReport)),
					new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public String generateHtmlReport(String marshalledDetailedReport) throws IOException, TransformerException {
		try (StringWriter stringWriter = new StringWriter()) {
			Transformer transformer = DetailedReportXmlDefiner.getHtmlTemplates().newTransformer();
			transformer.transform(new StreamSource(new StringReader(marshalledDetailedReport)), new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

}

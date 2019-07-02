package eu.europa.esig.dss.jaxb.simplereport;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.util.JAXBSource;
import javax.xml.transform.Result;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

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

		try (StringWriter writer = new StringWriter()) {
			marshaller.marshal(SimpleReportXmlDefiner.OBJECT_FACTORY.createSimpleReport(simpleReport), writer);
			return writer.toString();
		}
	}

	public String generateHtmlReport(XmlSimpleReport simpleReport) throws IOException, TransformerException, JAXBException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(simpleReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public void generateHtmlReport(XmlSimpleReport simpleReport, Result result)
			throws TransformerConfigurationException, IOException, TransformerException, JAXBException {
		Transformer transformer = SimpleReportXmlDefiner.getHtmlTemplates().newTransformer();
		transformer.transform(new JAXBSource(SimpleReportXmlDefiner.getJAXBContext(), SimpleReportXmlDefiner.OBJECT_FACTORY.createSimpleReport(simpleReport)),
				result);
	}

	public String generateHtmlReport(String marshalledSimpleReport) throws IOException, TransformerException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(marshalledSimpleReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public void generateHtmlReport(String marshalledSimpleReport, Result result) throws TransformerConfigurationException, IOException, TransformerException {
		Transformer transformer = SimpleReportXmlDefiner.getHtmlTemplates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledSimpleReport)), result);
	}

	public void generatePdfReport(XmlSimpleReport simpleReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = SimpleReportXmlDefiner.getPdfTemplates().newTransformer();
		transformer.transform(new JAXBSource(SimpleReportXmlDefiner.getJAXBContext(), SimpleReportXmlDefiner.OBJECT_FACTORY.createSimpleReport(simpleReport)),
				result);
	}

	public void generatePdfReport(String marshalledSimpleReport, Result result) throws IOException, TransformerException {
		Transformer transformer = SimpleReportXmlDefiner.getPdfTemplates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledSimpleReport)), result);
	}

}

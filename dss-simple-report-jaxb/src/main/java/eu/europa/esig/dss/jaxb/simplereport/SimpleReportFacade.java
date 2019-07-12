package eu.europa.esig.dss.jaxb.simplereport;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.util.JAXBSource;
import javax.xml.transform.Result;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.AbstractJaxbFacade;

public class SimpleReportFacade extends AbstractJaxbFacade<XmlSimpleReport> {

	public static SimpleReportFacade newFacade() {
		return new SimpleReportFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return SimpleReportXmlDefiner.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return SimpleReportXmlDefiner.getSchema();
	}

	@Override
	protected JAXBElement<XmlSimpleReport> wrap(XmlSimpleReport simpleReport) {
		return SimpleReportXmlDefiner.OBJECT_FACTORY.createSimpleReport(simpleReport);
	}

	public String generateHtmlReport(XmlSimpleReport simpleReport) throws IOException, TransformerException, JAXBException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(simpleReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public void generateHtmlReport(XmlSimpleReport simpleReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = SimpleReportXmlDefiner.getHtmlBootstrap3Templates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(simpleReport)), result);
	}

	public String generateHtmlReport(String marshalledSimpleReport) throws IOException, TransformerException {
		try (StringWriter stringWriter = new StringWriter()) {
			generateHtmlReport(marshalledSimpleReport, new StreamResult(stringWriter));
			return stringWriter.toString();
		}
	}

	public void generateHtmlReport(String marshalledSimpleReport, Result result) throws IOException, TransformerException {
		Transformer transformer = SimpleReportXmlDefiner.getHtmlBootstrap3Templates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledSimpleReport)), result);
	}

	public void generatePdfReport(XmlSimpleReport simpleReport, Result result) throws IOException, TransformerException, JAXBException {
		Transformer transformer = SimpleReportXmlDefiner.getPdfTemplates().newTransformer();
		transformer.transform(new JAXBSource(getJAXBContext(), wrap(simpleReport)), result);
	}

	public void generatePdfReport(String marshalledSimpleReport, Result result) throws IOException, TransformerException {
		Transformer transformer = SimpleReportXmlDefiner.getPdfTemplates().newTransformer();
		transformer.transform(new StreamSource(new StringReader(marshalledSimpleReport)), result);
	}

}

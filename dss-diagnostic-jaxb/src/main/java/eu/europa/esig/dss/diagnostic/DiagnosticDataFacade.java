package eu.europa.esig.dss.diagnostic;

import java.io.IOException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.jaxb.parsers.AbstractJaxbFacade;

public class DiagnosticDataFacade extends AbstractJaxbFacade<XmlDiagnosticData> {

	public static DiagnosticDataFacade newFacade() {
		return new DiagnosticDataFacade();
	}

	@Override
	protected JAXBContext getJAXBContext() throws JAXBException {
		return DiagnosticDataXmlDefiner.getJAXBContext();
	}

	@Override
	protected Schema getSchema() throws IOException, SAXException {
		return DiagnosticDataXmlDefiner.getSchema();
	}

	@Override
	protected JAXBElement<XmlDiagnosticData> wrap(XmlDiagnosticData diagnosticDataJaxb) {
		return DiagnosticDataXmlDefiner.OBJECT_FACTORY.createDiagnosticData(diagnosticDataJaxb);
	}
}

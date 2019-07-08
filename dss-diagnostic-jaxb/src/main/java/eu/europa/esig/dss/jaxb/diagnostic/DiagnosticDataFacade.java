package eu.europa.esig.dss.jaxb.diagnostic;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.stream.StreamSource;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.MarshallerBuilder;

public class DiagnosticDataFacade {
	
	public static DiagnosticDataFacade newFacade() {
		return new DiagnosticDataFacade();
	}

	public String marshall(XmlDiagnosticData diagnosticDataJaxb, boolean validate) throws JAXBException, IOException, SAXException {
		MarshallerBuilder marshallerBuilder = new MarshallerBuilder(DiagnosticDataXmlDefiner.getJAXBContext(), DiagnosticDataXmlDefiner.getSchema());
		marshallerBuilder.setIndent(true);
		marshallerBuilder.setValidate(validate);
		Marshaller marshaller = marshallerBuilder.buildMarshaller();

		try (StringWriter writer = new StringWriter()) {
			marshaller.marshal(DiagnosticDataXmlDefiner.OBJECT_FACTORY.createDiagnosticData(diagnosticDataJaxb), writer);
			return writer.toString();
		}
	}

	public XmlDiagnosticData unmarshall(File file) throws JAXBException, XMLStreamException, IOException, SAXException {
		try (FileInputStream fis = new FileInputStream(file)) {
			return unmarshall(new FileInputStream(file));
		}
	}

	@SuppressWarnings("unchecked")
	public XmlDiagnosticData unmarshall(InputStream is) throws JAXBException, XMLStreamException, IOException, SAXException {

		MarshallerBuilder builder = new MarshallerBuilder(DiagnosticDataXmlDefiner.getJAXBContext(), DiagnosticDataXmlDefiner.getSchema());
		builder.setValidate(true);
		Unmarshaller unmarshaller = builder.buildUnmarshaller();

		JAXBElement<XmlDiagnosticData> unmarshal = (JAXBElement<XmlDiagnosticData>) unmarshaller.unmarshal(avoidXXE(is));
		return unmarshal.getValue();
	}

	private XMLStreamReader avoidXXE(InputStream is) throws XMLStreamException {
		XMLInputFactory xif = XMLInputFactory.newFactory();
		xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
		xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
		return xif.createXMLStreamReader(new StreamSource(is));
	}

}

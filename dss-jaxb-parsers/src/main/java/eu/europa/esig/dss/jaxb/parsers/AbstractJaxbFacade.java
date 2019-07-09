package eu.europa.esig.dss.jaxb.parsers;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
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
import javax.xml.validation.Schema;

import org.xml.sax.SAXException;

public abstract class AbstractJaxbFacade<T> {

	protected abstract JAXBContext getJAXBContext() throws JAXBException;

	protected abstract Schema getSchema() throws IOException, SAXException;

	protected abstract JAXBElement<T> wrap(T jaxbObject);

	public String marshall(T jaxbObject, boolean validate) throws JAXBException, IOException, SAXException {
		Marshaller marshaller = getMarshaller(validate);

		try (StringWriter writer = new StringWriter()) {
			marshaller.marshal(wrap(jaxbObject), writer);
			return writer.toString();
		}
	}

	public void marshall(T jaxbObject, OutputStream os, boolean validate) throws JAXBException, SAXException, IOException {
		Marshaller marshaller = getMarshaller(validate);

		marshaller.marshal(wrap(jaxbObject), os);
	}

	private Marshaller getMarshaller(boolean validate) throws JAXBException, SAXException, IOException {
		MarshallerBuilder marshallerBuilder = new MarshallerBuilder(getJAXBContext(), getSchema());
		marshallerBuilder.setIndent(true);
		marshallerBuilder.setValidate(validate);
		return marshallerBuilder.buildMarshaller();
	}

	public T unmarshall(File file) throws JAXBException, XMLStreamException, IOException, SAXException {
		return unmarshall(file, true);
	}

	public T unmarshall(File file, boolean validate) throws JAXBException, XMLStreamException, IOException, SAXException {
		return unmarshall(new StreamSource(file), validate);
	}

	public T unmarshall(String xmlObject ) throws JAXBException, XMLStreamException, IOException, SAXException {
		return unmarshall(xmlObject, true);
	}

	public T unmarshall(String xmlObject, boolean validate) throws JAXBException, XMLStreamException, IOException, SAXException {
		return unmarshall(new StreamSource(new StringReader(xmlObject)), validate);
	}

	public T unmarshall(Source source) throws JAXBException, XMLStreamException, IOException, SAXException {
		return unmarshall(source, true);
	}

	@SuppressWarnings("unchecked")
	public T unmarshall(Source source, boolean validate) throws JAXBException, XMLStreamException, IOException, SAXException {
		MarshallerBuilder builder = new MarshallerBuilder(getJAXBContext(), getSchema());
		builder.setValidate(validate);
		Unmarshaller unmarshaller = builder.buildUnmarshaller();

		JAXBElement<T> unmarshal = (JAXBElement<T>) unmarshaller.unmarshal(avoidXXE(source));
		return unmarshal.getValue();
	}

	private XMLStreamReader avoidXXE(Source source) throws XMLStreamException {
		XMLInputFactory xif = XMLInputFactory.newFactory();
		xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
		xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
		return xif.createXMLStreamReader(source);
	}

}

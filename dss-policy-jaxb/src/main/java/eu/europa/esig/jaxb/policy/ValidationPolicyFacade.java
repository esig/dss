package eu.europa.esig.jaxb.policy;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.jaxb.parsers.MarshallerBuilder;

public class ValidationPolicyFacade {

	public static ValidationPolicyFacade newFacade() {
		return new ValidationPolicyFacade();
	}

	public ConstraintsParameters unmarshall(File file) throws JAXBException, XMLStreamException, IOException, SAXException {
		Unmarshaller unmarshaller = getUnmarshaller();

		return (ConstraintsParameters) unmarshaller.unmarshal(avoidXXE(new StreamSource(file)));
	}

	public ConstraintsParameters unmarshall(InputStream inputStream) throws JAXBException, XMLStreamException, IOException, SAXException {
		Unmarshaller unmarshaller = getUnmarshaller();

		return (ConstraintsParameters) unmarshaller.unmarshal(avoidXXE(new StreamSource(inputStream)));
	}

	private Unmarshaller getUnmarshaller() throws JAXBException, IOException, SAXException {
		MarshallerBuilder builder = new MarshallerBuilder(ValidationPolicyXmlDefiner.getJAXBContext(), ValidationPolicyXmlDefiner.getSchema());
		builder.setValidate(true);
		return builder.buildUnmarshaller();
	}

	private XMLStreamReader avoidXXE(Source source) throws XMLStreamException {
		XMLInputFactory xif = XMLInputFactory.newFactory();
		xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
		xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
		return xif.createXMLStreamReader(source);
	}

}

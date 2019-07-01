package eu.europa.esig.jaxb.policy;

import java.io.File;
import java.io.IOException;

import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.stream.StreamSource;

import org.xml.sax.SAXException;

import eu.europa.esig.dss.MarshallerBuilder;

public class ValidationPolicyFacade {

	public static ValidationPolicyFacade newFacade() {
		return new ValidationPolicyFacade();
	}

	public ConstraintsParameters unmarshall(File file) throws JAXBException, XMLStreamException, IOException, SAXException {

		MarshallerBuilder builder = new MarshallerBuilder(ValidationPolicyXmlDefiner.getJAXBContext(), ValidationPolicyXmlDefiner.getSchema());
		builder.setValidate(true);
		Unmarshaller unmarshaller = builder.buildUnmarshaller();

		return (ConstraintsParameters) unmarshaller.unmarshal(avoidXXE(file));
	}

	private XMLStreamReader avoidXXE(File file) throws XMLStreamException {
		XMLInputFactory xif = XMLInputFactory.newFactory();
		xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
		xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
		return xif.createXMLStreamReader(new StreamSource(file));
	}

}

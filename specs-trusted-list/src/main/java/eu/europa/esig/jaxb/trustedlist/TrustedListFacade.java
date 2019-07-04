package eu.europa.esig.jaxb.trustedlist;

import java.io.InputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;

import org.xml.sax.SAXException;

import eu.europa.esig.jaxb.trustedlist.tsl.TrustStatusListType;

public class TrustedListFacade {

	public static TrustedListFacade newFacade() {
		return new TrustedListFacade();
	}

	@SuppressWarnings("unchecked")
	public TrustStatusListType unmarshall(InputStream is, boolean validate) throws JAXBException, XMLStreamException, SAXException {
		JAXBContext jaxbContext = TrustedListUtils.getJAXBContext();
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		if (validate) {
			unmarshaller.setSchema(TrustedListUtils.getSchema());
		}
		JAXBElement<TrustStatusListType> jaxbElement = (JAXBElement<TrustStatusListType>) unmarshaller.unmarshal(avoidXXE(new StreamSource(is)));
		return jaxbElement.getValue();
	}

	private XMLStreamReader avoidXXE(Source source) throws XMLStreamException {
		XMLInputFactory xif = XMLInputFactory.newFactory();
		xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
		xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
		return xif.createXMLStreamReader(source);
	}

}

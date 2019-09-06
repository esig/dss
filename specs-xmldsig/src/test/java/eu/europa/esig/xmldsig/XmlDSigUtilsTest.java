package eu.europa.esig.xmldsig;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.xmldsig.jaxb.SignatureType;

public class XmlDSigUtilsTest {

	@Test
	@SuppressWarnings("unchecked")
	public void test() throws JAXBException, SAXException {

		File xmldsigFile = new File("src/test/resources/XmlAliceSig.xml");

		JAXBContext jc = XmlDSigUtils.getJAXBContext();
		assertNotNull(jc);

		Schema schema = XmlDSigUtils.getSchema();
		assertNotNull(schema);

		Unmarshaller unmarshaller = jc.createUnmarshaller();
		unmarshaller.setSchema(schema);

		JAXBElement<SignatureType> unmarshalled = (JAXBElement<SignatureType>) unmarshaller.unmarshal(xmldsigFile);
		assertNotNull(unmarshalled);

		Marshaller marshaller = jc.createMarshaller();
		marshaller.setSchema(schema);

		StringWriter sw = new StringWriter();
		marshaller.marshal(unmarshalled, sw);

		String xmldsigString = sw.toString();

		JAXBElement<SignatureType> unmarshalled2 = (JAXBElement<SignatureType>) unmarshaller.unmarshal(new StringReader(xmldsigString));
		assertNotNull(unmarshalled2);
	}

	@Test
	public void getJAXBContext() throws JAXBException {
		assertNotNull(XmlDSigUtils.getJAXBContext());
		// cached
		assertNotNull(XmlDSigUtils.getJAXBContext());
	}

	@Test
	public void getSchema() throws SAXException {
		assertNotNull(XmlDSigUtils.getSchema());
		// cached
		assertNotNull(XmlDSigUtils.getSchema());
	}

}

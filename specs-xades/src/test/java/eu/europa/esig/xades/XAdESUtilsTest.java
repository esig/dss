package eu.europa.esig.xades;

import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.StringReader;
import java.io.StringWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;

import org.junit.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.xmldsig.jaxb.SignatureType;

public class XAdESUtilsTest {

	@Test
	@SuppressWarnings("unchecked")
	public void test() throws JAXBException, SAXException {

		File xmldsigFile = new File("src/test/resources/xades-lta.xml");

		JAXBContext jc = XAdESUtils.getJAXBContext();
		assertNotNull(jc);

		Schema schema = XAdESUtils.getSchema();
		assertNotNull(schema);

		Unmarshaller unmarshaller = jc.createUnmarshaller();
		unmarshaller.setSchema(schema);

		JAXBElement<SignatureType> unmarshalled = (JAXBElement<SignatureType>) unmarshaller.unmarshal(xmldsigFile);
		assertNotNull(unmarshalled);

		Marshaller marshaller = jc.createMarshaller();
		marshaller.setSchema(schema);

		StringWriter sw = new StringWriter();
		marshaller.marshal(unmarshalled, sw);

		String xadesString = sw.toString();

		JAXBElement<SignatureType> unmarshalled2 = (JAXBElement<SignatureType>) unmarshaller.unmarshal(new StringReader(xadesString));
		assertNotNull(unmarshalled2);
	}

	@Test
	public void getSchema() throws SAXException {
		assertNotNull(XAdESUtils.getSchema());
		// cached
		assertNotNull(XAdESUtils.getSchema());
	}

	@Test
	public void getSchemaETSI_EN_319_132() throws SAXException {
		assertNotNull(XAdESUtils.getSchemaETSI_EN_319_132());
		// cached
		assertNotNull(XAdESUtils.getSchemaETSI_EN_319_132());
	}

}

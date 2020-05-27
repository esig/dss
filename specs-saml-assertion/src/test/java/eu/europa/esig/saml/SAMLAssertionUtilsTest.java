package eu.europa.esig.saml;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.saml.jaxb.assertion.AssertionType;

public class SAMLAssertionUtilsTest {

	private static SAMLAssertionUtils samlAssertionUtils;

	@BeforeAll
	public static void init() {
		samlAssertionUtils = SAMLAssertionUtils.getInstance();
	}

	@SuppressWarnings("unchecked")
	@Test
	public void test() throws JAXBException, SAXException {
		JAXBContext jc = samlAssertionUtils.getJAXBContext();
		assertNotNull(jc);

		Schema schema = samlAssertionUtils.getSchema();
		assertNotNull(schema);

		File file = new File("src/test/resources/sample-saml-assertion.xml");

		Unmarshaller unmarshaller = jc.createUnmarshaller();
		unmarshaller.setSchema(schema);

		JAXBElement<AssertionType> unmarshalled = (JAXBElement<AssertionType>) unmarshaller.unmarshal(file);
		assertNotNull(unmarshalled);
	}

}

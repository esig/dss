package eu.europa.esig.saml;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.validation.Schema;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

public class SoapEnvelopeUtilsTest {

	private static SoapEnvelopeUtils soapEnvelopeUtils;

	@BeforeAll
	public static void init() {
		soapEnvelopeUtils = SoapEnvelopeUtils.getInstance();
	}

	@Test
	public void test() throws JAXBException, SAXException {
		JAXBContext jaxbContext = soapEnvelopeUtils.getJAXBContext();
		assertNotNull(jaxbContext);

		Schema schema = soapEnvelopeUtils.getSchema();
		assertNotNull(schema);
	}

}

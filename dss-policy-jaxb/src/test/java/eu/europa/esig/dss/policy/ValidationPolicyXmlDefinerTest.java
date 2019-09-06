package eu.europa.esig.dss.policy;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import javax.xml.bind.JAXBException;

import org.junit.Test;
import org.xml.sax.SAXException;

public class ValidationPolicyXmlDefinerTest {

	@Test
	public void getJAXBContext() throws SAXException, JAXBException {
		assertNotNull(ValidationPolicyXmlDefiner.getJAXBContext());
		assertNotNull(ValidationPolicyXmlDefiner.getJAXBContext());
	}

	@Test
	public void getSchema() throws SAXException, IOException {
		assertNotNull(ValidationPolicyXmlDefiner.getSchema());
		assertNotNull(ValidationPolicyXmlDefiner.getSchema());
	}

}

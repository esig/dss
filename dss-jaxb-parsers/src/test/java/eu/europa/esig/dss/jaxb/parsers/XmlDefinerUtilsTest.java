package eu.europa.esig.dss.jaxb.parsers;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import javax.xml.transform.TransformerConfigurationException;

import org.junit.jupiter.api.Test;
import org.xml.sax.SAXException;

public class XmlDefinerUtilsTest {

	@Test
	public void getSecureSchemaFactory() throws SAXException {
		assertNotNull(XmlDefinerUtils.getSecureSchemaFactory());
	}

	@Test
	public void getSecureTransformerFactory() throws TransformerConfigurationException {
		assertNotNull(XmlDefinerUtils.getSecureTransformerFactory());
	}

}

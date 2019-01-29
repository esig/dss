package eu.europa.esig.dss.jaxb.simplereport;

import static org.junit.Assert.assertNotNull;

import java.io.File;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.junit.Test;
import org.xml.sax.SAXException;

public class XSDValidatorTest {

	@Test
	public void validateXSD() throws SAXException {
		SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		Schema schema = factory.newSchema(new StreamSource(new File("src/main/resources/xsd/SimpleReport.xsd")));
		Validator validator = schema.newValidator();
		assertNotNull(validator);
	}

}

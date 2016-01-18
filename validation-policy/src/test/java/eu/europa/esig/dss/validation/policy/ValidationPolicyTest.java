package eu.europa.esig.dss.validation.policy;

import static org.junit.Assert.assertNotNull;

import java.io.File;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.junit.Test;

import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class ValidationPolicyTest {

	@Test
	public void test1() throws Exception {

		SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		Schema schema = sf.newSchema(new File("src/main/resources/policy/policy.xsd"));

		JAXBContext jaxbContext = JAXBContext.newInstance(eu.europa.esig.jaxb.policy.ObjectFactory.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		unmarshaller.setSchema(schema);

		ConstraintsParameters constraints = (ConstraintsParameters) unmarshaller.unmarshal(new File("src/main/resources/policy/constraint.xml"));
		assertNotNull(constraints);

		EtsiValidationPolicy policy = new EtsiValidationPolicy(constraints);

		assertNotNull(policy);
	}
}

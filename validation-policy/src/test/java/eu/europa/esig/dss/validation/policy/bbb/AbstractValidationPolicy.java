package eu.europa.esig.dss.validation.policy.bbb;

import static org.junit.Assert.assertNotNull;

import java.io.File;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class AbstractValidationPolicy {

	public ValidationPolicy getPolicy() throws Exception {
		SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		Schema schema = sf.newSchema(new File("src/main/resources/policy/policy.xsd"));

		JAXBContext jaxbContext = JAXBContext.newInstance(eu.europa.esig.jaxb.policy.ObjectFactory.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		unmarshaller.setSchema(schema);

		ConstraintsParameters constraints = (ConstraintsParameters) unmarshaller.unmarshal(new File("src/main/resources/policy/constraint.xml"));
		assertNotNull(constraints);

		return new EtsiValidationPolicy(constraints);
	}

}

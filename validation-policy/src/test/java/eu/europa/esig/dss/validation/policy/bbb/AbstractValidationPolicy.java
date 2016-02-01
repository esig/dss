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
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;
import eu.europa.esig.jaxb.policy.MultiValuesConstraint;
import eu.europa.esig.jaxb.policy.ValueConstraint;

public class AbstractValidationPolicy {

	public ConstraintsParameters getConstraintsParameters() throws Exception {
		SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		Schema schema = sf.newSchema(new File("src/main/resources/policy/policy.xsd"));

		JAXBContext jaxbContext = JAXBContext.newInstance(eu.europa.esig.jaxb.policy.ObjectFactory.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		unmarshaller.setSchema(schema);

		ConstraintsParameters constraints = (ConstraintsParameters) unmarshaller.unmarshal(new File("src/main/resources/policy/constraint.xml"));
		assertNotNull(constraints);

		return constraints;
	}

	public ValidationPolicy getPolicy() throws Exception {
		return new EtsiValidationPolicy(getConstraintsParameters());
	}

	public MultiValuesConstraint createMultiValueConstraint(Level level) {
		MultiValuesConstraint result = new MultiValuesConstraint();
		result.setLevel(level);
		return result;
	}

	public ValueConstraint createValueConstraint(Level level) {
		ValueConstraint result = new ValueConstraint();
		result.setLevel(level);
		return result;
	}

	public LevelConstraint createLevelConstraint(Level level) {
		LevelConstraint result = new LevelConstraint();
		result.setLevel(level);
		return result;
	}

}

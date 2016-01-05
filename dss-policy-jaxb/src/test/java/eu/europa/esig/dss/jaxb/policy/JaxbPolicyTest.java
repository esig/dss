package eu.europa.esig.dss.jaxb.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileOutputStream;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.junit.Test;

import eu.europa.esig.jaxb.policy.Algo;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class JaxbPolicyTest {

	@Test
	public void testUnmarshalling() throws Exception {
		ConstraintsParameters constraintsParameters = unmarshal(new File("src/test/resources/constraint.xml"));

		Algo algo = constraintsParameters.getSignatureConstraints().getCryptographic().getMiniPublicKeySize().getAlgo().get(0);
		assertNotNull(algo);
		String algoName = algo.getValue();
		assertEquals("DSA", algoName);
		assertEquals("128", algo.getSize());

		JAXBContext jc = JAXBContext.newInstance("eu.europa.esig.jaxb.policy");
		Marshaller marshaller = jc.createMarshaller();
		marshaller.marshal(constraintsParameters, new FileOutputStream("target/constraint.xml"));
	}

	@Test
	public void testUnmarshalCoreValidation() throws Exception {
		unmarshal(new File("src/test/resources/constraint-core-validation.xml"));
	}

	// TODO @Test
	public void testUnmarshalModel() throws Exception {
		unmarshal(new File("src/test/resources/constraints_MODEL.xml"));
	}

	public ConstraintsParameters unmarshal(File file) throws Exception {
		JAXBContext jc = JAXBContext.newInstance("eu.europa.esig.jaxb.policy");
		Unmarshaller unmarshaller = jc.createUnmarshaller();

		SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		Schema schema = sf.newSchema(new File("src/main/xsd/policy.xsd"));
		unmarshaller.setSchema(schema);

		ConstraintsParameters constraintsParamaters = (ConstraintsParameters) unmarshaller.unmarshal(file);
		assertNotNull(constraintsParamaters);
		return constraintsParamaters;
	}

}

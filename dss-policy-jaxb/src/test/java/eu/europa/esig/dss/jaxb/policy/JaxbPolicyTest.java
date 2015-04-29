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
		File constraintsFile = new File("src/test/resources/constraint.xml");
		JAXBContext jc = JAXBContext.newInstance("eu.europa.esig.jaxb.policy");
		Unmarshaller unmarshaller = jc.createUnmarshaller();

		SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		Schema schema = sf.newSchema(new File("src/main/xsd/policy.xsd"));
		unmarshaller.setSchema(schema);

		ConstraintsParameters constraintsParamaters = (ConstraintsParameters) unmarshaller.unmarshal(constraintsFile);
		assertNotNull(constraintsParamaters);

		Algo algo = constraintsParamaters.getMainSignature().getCryptographic().getMiniPublicKeySize().getAlgo().get(0);
		assertNotNull(algo);
		String algoName = algo.getValue();
		assertEquals("DSA", algoName);
		assertEquals("128", algo.getSize());

		Marshaller marshaller = jc.createMarshaller();
		marshaller.marshal(constraintsParamaters, new FileOutputStream("target/constraint.xml"));
	}

}

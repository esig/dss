package eu.europa.esig.dss.jaxb.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileOutputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.junit.Test;

import eu.europa.esig.jaxb.policy.Algo;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class JaxbPolicyTest {

	@Test
	public void testUnmarshalling() throws Exception {
		File constraintsFile = new File("src/test/resources/constraint.xml");
		JAXBContext jc = JAXBContext.newInstance("eu.europa.esig.jaxb.policy");
		Unmarshaller unmarshaller = jc.createUnmarshaller();
		ConstraintsParameters constraintsParamaters = (ConstraintsParameters) unmarshaller.unmarshal(constraintsFile);
		assertNotNull(constraintsParamaters);

		// Problem to read element with optional attributes
		Algo algo = constraintsParamaters.getMainSignature().getCryptographic().getAcceptableDigestAlgo().get(0);
		assertNotNull(algo);
		String algoName = algo.getValue();
		assertEquals("SHA1", algoName);

		Marshaller marshaller = jc.createMarshaller();
		marshaller.marshal(constraintsParamaters, new FileOutputStream("target/constraint.xml"));
	}

}

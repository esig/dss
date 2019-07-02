package eu.europa.esig.dss.jaxb.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.FileOutputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;

import org.junit.Test;

import eu.europa.esig.jaxb.policy.Algo;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.Model;
import eu.europa.esig.jaxb.policy.ModelConstraint;
import eu.europa.esig.jaxb.policy.RevocationConstraints;
import eu.europa.esig.jaxb.policy.TimeConstraint;
import eu.europa.esig.jaxb.policy.TimeUnit;
import eu.europa.esig.jaxb.policy.ValidationPolicyFacade;
import eu.europa.esig.jaxb.policy.ValidationPolicyXmlDefiner;

public class JaxbPolicyTest {

	@Test
	public void testUnmarshalling() throws Exception {
		ConstraintsParameters constraintsParameters = ValidationPolicyFacade.newFacade().unmarshall(new File("src/test/resources/constraint.xml"));

		Algo algo = constraintsParameters.getSignatureConstraints().getBasicSignatureConstraints().getCryptographic().getMiniPublicKeySize().getAlgo().get(0);
		assertNotNull(algo);
		String algoName = algo.getValue();
		assertEquals("DSA", algoName);
		assertEquals("128", algo.getSize());

		JAXBContext jc = ValidationPolicyXmlDefiner.getJAXBContext();
		Marshaller marshaller = jc.createMarshaller();
		marshaller.marshal(constraintsParameters, new FileOutputStream("target/constraint.xml"));
	}
	
	@Test
	public void testUnmarshallingWithModel() throws Exception {
		ConstraintsParameters constraintsParameters = ValidationPolicyFacade.newFacade().unmarshall(new File("src/test/resources/constraint.xml"));

		ModelConstraint mc = new ModelConstraint();
		mc.setValue(Model.SHELL);
		constraintsParameters.setModel(mc);
		
		JAXBContext jc = ValidationPolicyXmlDefiner.getJAXBContext();
		Marshaller marshaller = jc.createMarshaller();
		marshaller.marshal(constraintsParameters, new FileOutputStream("target/constraint.xml"));
		
		ConstraintsParameters cp = ValidationPolicyFacade.newFacade().unmarshall(new File("target/constraint.xml"));
		assertNotNull(cp);
		assertNotNull(cp.getModel());
		assertEquals(mc.getValue(), cp.getModel().getValue());
	}

	@Test
	public void testUnmarshalCoreValidation() throws Exception {
		ValidationPolicyFacade.newFacade().unmarshall(new File("src/test/resources/constraint-core-validation.xml"));
	}

	@Test
	public void testUnmarshalConstraint() throws Exception {
		ConstraintsParameters constraintsParameters = ValidationPolicyFacade.newFacade().unmarshall(new File("src/test/resources/constraint.xml"));
		RevocationConstraints revocation = constraintsParameters.getRevocation();
		assertNotNull(revocation);
		TimeConstraint revocationFreshness = revocation.getRevocationFreshness();
		assertNotNull(revocationFreshness);
		assertEquals(Level.FAIL, revocationFreshness.getLevel());
		assertEquals(TimeUnit.DAYS, revocationFreshness.getUnit());
		assertNotNull(revocationFreshness.getValue());
		assertEquals(0, revocationFreshness.getValue().intValue());
	}

	// TODO @Test
	public void testUnmarshalModel() throws Exception {
		ValidationPolicyFacade.newFacade().unmarshall(new File("src/test/resources/constraints_MODEL.xml"));
	}

}

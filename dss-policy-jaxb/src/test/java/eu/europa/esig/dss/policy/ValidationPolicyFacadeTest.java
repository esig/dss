package eu.europa.esig.dss.policy;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import javax.xml.bind.JAXBException;
import javax.xml.bind.UnmarshalException;
import javax.xml.stream.XMLStreamException;

import org.junit.Test;
import org.xml.sax.SAXException;

import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.Model;
import eu.europa.esig.dss.policy.jaxb.ModelConstraint;
import eu.europa.esig.dss.policy.jaxb.RevocationConstraints;
import eu.europa.esig.dss.policy.jaxb.TimeConstraint;
import eu.europa.esig.dss.policy.jaxb.TimeUnit;

public class ValidationPolicyFacadeTest {

	@Test
	public void testUnmarshalling() throws Exception {
		ConstraintsParameters constraintsParameters = ValidationPolicyFacade.newFacade().unmarshall(new File("src/test/resources/constraint.xml"));

		Algo algo = constraintsParameters.getSignatureConstraints().getBasicSignatureConstraints().getCryptographic().getMiniPublicKeySize().getAlgo().get(0);
		assertNotNull(algo);
		String algoName = algo.getValue();
		assertEquals("DSA", algoName);
		assertEquals(128, algo.getSize().longValue());

		String marshall = ValidationPolicyFacade.newFacade().marshall(constraintsParameters);
		assertNotNull(marshall);
	}
	
	@Test
	public void testUnmarshallingWithModel() throws Exception {
		ConstraintsParameters constraintsParameters = ValidationPolicyFacade.newFacade().unmarshall(new File("src/test/resources/constraint.xml"));

		ModelConstraint mc = new ModelConstraint();
		mc.setValue(Model.SHELL);
		constraintsParameters.setModel(mc);

		String marshall = ValidationPolicyFacade.newFacade().marshall(constraintsParameters);
		assertNotNull(marshall);
		
		ConstraintsParameters cp = ValidationPolicyFacade.newFacade().unmarshall(marshall);
		assertNotNull(cp);
		assertNotNull(cp.getModel());
		assertEquals(mc.getValue(), cp.getModel().getValue());
	}

	@Test
	public void testUnmarshalCoreValidation() throws Exception {
		ConstraintsParameters constraintsParameters = ValidationPolicyFacade.newFacade().unmarshall(new File("src/test/resources/constraint-core-validation.xml"));
		assertNotNull(constraintsParameters);
	}

	@Test
	public void getDefaultValidationPolicy() throws JAXBException, XMLStreamException, IOException, SAXException {
		assertNotNull(ValidationPolicyFacade.newFacade().getDefaultValidationPolicy());
	}

	@Test
	public void getTrustedListValidationPolicy() throws JAXBException, XMLStreamException, IOException, SAXException {
		assertNotNull(ValidationPolicyFacade.newFacade().getTrustedListValidationPolicy());
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

	@Test(expected = UnmarshalException.class)
	public void testInvalid() throws Exception {
		ValidationPolicyFacade.newFacade().unmarshall(new File("src/test/resources/invalid-policy.xml"));
	}

	@Test(expected = NullPointerException.class)
	public void unmarshallNullIS() throws Exception {
		ValidationPolicyFacade.newFacade().unmarshall((InputStream) null);
	}

	@Test(expected = NullPointerException.class)
	public void unmarshallNullFile() throws Exception {
		ValidationPolicyFacade.newFacade().unmarshall((File) null);
	}

	@Test(expected = NullPointerException.class)
	public void unmarshallNullString() throws Exception {
		ValidationPolicyFacade.newFacade().unmarshall((String) null);
	}

	@Test(expected = NullPointerException.class)
	public void marshallNull() throws Exception {
		ValidationPolicyFacade.newFacade().marshall(null);
	}

	@Test(expected = NullPointerException.class)
	public void marshallNull2() throws Exception {
		ValidationPolicyFacade.newFacade().marshall(null, null);
	}

}

/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

import javax.xml.bind.JAXBException;
import javax.xml.bind.UnmarshalException;
import javax.xml.stream.XMLStreamException;

import org.junit.jupiter.api.Test;
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
		assertEquals(128, algo.getSize());

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
		ValidationPolicy trustedListValidationPolicy = ValidationPolicyFacade.newFacade().getTrustedListValidationPolicy();
		assertNotNull(trustedListValidationPolicy);
		assertEquals("Policy to validate Trusted Lists", trustedListValidationPolicy.getPolicyDescription());
	}

	@Test
	public void incorrectPath() throws JAXBException, XMLStreamException, IOException, SAXException {
		assertThrows(NullPointerException.class, () -> ValidationPolicyFacade.newFacade().getValidationPolicy("aaaa"));
		assertThrows(NullPointerException.class, () -> ValidationPolicyFacade.newFacade().getValidationPolicy((InputStream) null));
		assertThrows(NullPointerException.class, () -> ValidationPolicyFacade.newFacade().getValidationPolicy((File) null));
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

	@Test
	public void testInvalid() throws Exception {
		assertThrows(UnmarshalException.class, () -> ValidationPolicyFacade.newFacade().unmarshall(new File("src/test/resources/invalid-policy.xml")));
	}

	@Test
	public void unmarshallNullIS() throws Exception {
		assertThrows(NullPointerException.class, () -> ValidationPolicyFacade.newFacade().unmarshall((InputStream) null));
	}

	@Test
	public void unmarshallNullFile() throws Exception {
		assertThrows(NullPointerException.class, () -> ValidationPolicyFacade.newFacade().unmarshall((File) null));
	}

	@Test
	public void unmarshallNullString() throws Exception {
		assertThrows(NullPointerException.class, () -> ValidationPolicyFacade.newFacade().unmarshall((String) null));
	}

	@Test
	public void marshallNull() throws Exception {
		assertThrows(NullPointerException.class, () -> ValidationPolicyFacade.newFacade().marshall(null));
	}

	@Test
	public void marshallNull2() throws Exception {
		assertThrows(NullPointerException.class, () -> ValidationPolicyFacade.newFacade().marshall(null, null));
	}

}

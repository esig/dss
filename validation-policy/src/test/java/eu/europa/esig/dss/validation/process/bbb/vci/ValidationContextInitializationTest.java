package eu.europa.esig.dss.validation.process.bbb.vci;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlVCI;
import eu.europa.esig.dss.jaxb.diagnostic.XmlPolicy;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.bbb.LoadPolicyUtils;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class ValidationContextInitializationTest {

	@Test
	public void signaturePolicyIdentifierCheck() throws Exception {
		XmlSignature sig = new XmlSignature();
		EtsiValidationPolicy policy = LoadPolicyUtils.loadPolicy();

		ValidationContextInitialization vci = new ValidationContextInitialization(new SignatureWrapper(sig),
				Context.SIGNATURE, policy);
		XmlVCI result = vci.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		XmlPolicy xmlPolicy = new XmlPolicy();
		xmlPolicy.setId("IMPLICIT_POLICY");
		sig.setPolicy(xmlPolicy);
		vci = new ValidationContextInitialization(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = vci.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		xmlPolicy.setId("");
		sig.setPolicy(xmlPolicy);
		vci = new ValidationContextInitialization(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = vci.execute();
		assertEquals(Indication.INDETERMINATE, result.getConclusion().getIndication());
		assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, result.getConclusion().getSubIndication());

		xmlPolicy.setId("OTHER_POLICY");
		sig.setPolicy(xmlPolicy);
		vci = new ValidationContextInitialization(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = vci.execute();
		assertEquals(Indication.INDETERMINATE, result.getConclusion().getIndication());
		assertEquals(SubIndication.POLICY_PROCESSING_ERROR, result.getConclusion().getSubIndication());

	}

	@Test
	public void signaturePolicyIdentifiedCheck() throws Exception {
		XmlSignature sig = new XmlSignature();
		EtsiValidationPolicy policy = LoadPolicyUtils.loadPolicy();

		/*
		 * XmlPolicy xmlPolicy = new XmlPolicy();
		 * xmlPolicy.setId("IMPLICIT_POLICY"); xmlPolicy.setIdentified(true);
		 * sig.setPolicy(xmlPolicy); ValidationContextInitialization vci = new
		 * ValidationContextInitialization(new SignatureWrapper(sig),
		 * Context.SIGNATURE, policy); XmlVCI result = vci.execute();
		 * assertEquals(Indication.PASSED,
		 * result.getConclusion().getIndication());
		 * 
		 * xmlPolicy.setId(null); xmlPolicy.setIdentified(true);
		 * sig.setPolicy(xmlPolicy); vci = new
		 * ValidationContextInitialization(new SignatureWrapper(sig),
		 * Context.SIGNATURE, policy); result = vci.execute();
		 * assertEquals(Indication.INDETERMINATE,
		 * result.getConclusion().getIndication());
		 * assertEquals(SubIndication.POLICY_PROCESSING_ERROR,
		 * result.getConclusion().getSubIndication());
		 * 
		 * xmlPolicy.setId("OTHER_POLICY"); xmlPolicy.setIdentified(true);
		 * sig.setPolicy(xmlPolicy); vci = new
		 * ValidationContextInitialization(new SignatureWrapper(sig),
		 * Context.SIGNATURE, policy); result = vci.execute();
		 * assertEquals(Indication.INDETERMINATE,
		 * result.getConclusion().getIndication());
		 * assertEquals(SubIndication.POLICY_PROCESSING_ERROR,
		 * result.getConclusion().getSubIndication());
		 * 
		 * xmlPolicy.setId("OTHER_POLICY"); xmlPolicy.setIdentified(false);
		 * sig.setPolicy(xmlPolicy); vci = new
		 * ValidationContextInitialization(new SignatureWrapper(sig),
		 * Context.SIGNATURE, policy); result = vci.execute();
		 * assertEquals(Indication.INDETERMINATE,
		 * result.getConclusion().getIndication());
		 * assertEquals(SubIndication.POLICY_PROCESSING_ERROR,
		 * result.getConclusion().getSubIndication());
		 * 
		 * xmlPolicy.setId(null); xmlPolicy.setIdentified(false);
		 * sig.setPolicy(xmlPolicy); vci = new
		 * ValidationContextInitialization(new SignatureWrapper(sig),
		 * Context.SIGNATURE, policy); result = vci.execute();
		 * assertEquals(Indication.INDETERMINATE,
		 * result.getConclusion().getIndication());
		 * assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE,
		 * result.getConclusion().getSubIndication());
		 */

		// TODO: why is it PASSED ?

		XmlPolicy xmlPolicy = new XmlPolicy();
		xmlPolicy.setId("IMPLICIT_POLICY");
		xmlPolicy.setIdentified(false);
		sig = new XmlSignature();
		sig.setPolicy(xmlPolicy);
		assertFalse(sig.getPolicy().isIdentified());
		ValidationContextInitialization vci = new ValidationContextInitialization(new SignatureWrapper(sig),
				Context.SIGNATURE, policy);
		XmlVCI result = vci.execute();
		assertEquals(Indication.INDETERMINATE, result.getConclusion().getIndication());

	}

	@Test
	public void signaturePolicyHashValidCheck() throws Exception {
		XmlSignature sig = new XmlSignature();
		EtsiValidationPolicy policy = LoadPolicyUtils.loadPolicy();

		XmlPolicy xmlPolicy = new XmlPolicy();
		xmlPolicy.setId("IMPLICIT_POLICY");
		xmlPolicy.setStatus(true);
		sig.setPolicy(xmlPolicy);
		ValidationContextInitialization vci = new ValidationContextInitialization(new SignatureWrapper(sig),
				Context.SIGNATURE, policy);
		XmlVCI result = vci.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		xmlPolicy.setId(null);
		sig.setPolicy(xmlPolicy);
		vci = new ValidationContextInitialization(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = vci.execute();
		assertEquals(Indication.INDETERMINATE, result.getConclusion().getIndication());
		assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, result.getConclusion().getSubIndication());

		xmlPolicy.setStatus(false);
		sig.setPolicy(xmlPolicy);
		vci = new ValidationContextInitialization(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = vci.execute();
		assertEquals(Indication.INDETERMINATE, result.getConclusion().getIndication());
		assertEquals(SubIndication.SIGNATURE_POLICY_NOT_AVAILABLE, result.getConclusion().getSubIndication());

	}

}

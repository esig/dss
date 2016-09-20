package eu.europa.esig.dss.validation.process.bbb.cv;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.diagnostic.XmlBasicSignature;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.bbb.LoadPolicyUtils;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class CryptographicVerificationTest {

	@Test
	public void signatureIntactCheck() throws Exception {
		XmlSignature sig = new XmlSignature();
		EtsiValidationPolicy policy = LoadPolicyUtils.loadPolicy();

		XmlBasicSignature basicsig = new XmlBasicSignature();
		basicsig.setReferenceDataFound(true);
		basicsig.setReferenceDataIntact(true);

		basicsig.setSignatureIntact(true);
		sig.setBasicSignature(basicsig);
		CryptographicVerification cv = new CryptographicVerification(new SignatureWrapper(sig), Context.SIGNATURE,
				policy);
		XmlCV result = cv.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		basicsig.setSignatureIntact(false);
		sig.setBasicSignature(basicsig);
		cv = new CryptographicVerification(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = cv.execute();
		assertEquals(Indication.FAILED, result.getConclusion().getIndication());

	}

	@Test
	public void referenceDataIntactCheck() throws Exception {
		XmlSignature sig = new XmlSignature();
		EtsiValidationPolicy policy = LoadPolicyUtils.loadPolicy();

		XmlBasicSignature basicsig = new XmlBasicSignature();
		basicsig.setReferenceDataFound(true);
		basicsig.setSignatureIntact(true);

		basicsig.setReferenceDataIntact(true);
		sig.setBasicSignature(basicsig);
		CryptographicVerification cv = new CryptographicVerification(new SignatureWrapper(sig), Context.SIGNATURE,
				policy);
		XmlCV result = cv.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		basicsig.setSignatureIntact(false);
		sig.setBasicSignature(basicsig);
		cv = new CryptographicVerification(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = cv.execute();
		assertEquals(Indication.FAILED, result.getConclusion().getIndication());

	}

	@Test
	public void referenceDataExistenceCheck() throws Exception {
		XmlSignature sig = new XmlSignature();
		EtsiValidationPolicy policy = LoadPolicyUtils.loadPolicy();

		XmlBasicSignature basicsig = new XmlBasicSignature();
		basicsig.setSignatureIntact(true);
		basicsig.setReferenceDataIntact(true);

		sig.setBasicSignature(basicsig);
		CryptographicVerification cv = new CryptographicVerification(new SignatureWrapper(sig), Context.SIGNATURE,
				policy);
		XmlCV result = cv.execute();
		assertEquals(Indication.INDETERMINATE, result.getConclusion().getIndication());
		assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, result.getConclusion().getSubIndication());

		basicsig.setReferenceDataFound(true);
		sig.setBasicSignature(basicsig);
		cv = new CryptographicVerification(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = cv.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		basicsig.setSignatureIntact(false);
		sig.setBasicSignature(basicsig);
		cv = new CryptographicVerification(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = cv.execute();
		assertEquals(Indication.FAILED, result.getConclusion().getIndication());

	}

}

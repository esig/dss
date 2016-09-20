package eu.europa.esig.dss.validation.process.bbb.fc;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import eu.europa.esig.dss.jaxb.detailedreport.XmlFC;
import eu.europa.esig.dss.jaxb.diagnostic.XmlSignature;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.process.bbb.LoadPolicyUtils;
import eu.europa.esig.dss.validation.reports.wrapper.SignatureWrapper;

public class FormatCheckingTest {

	@Test
	public void validFormat() throws Exception {
		EtsiValidationPolicy policy = LoadPolicyUtils.loadPolicy();
		XmlSignature sig = new XmlSignature();
		sig.setSignatureFormat("CAdES_BASELINE_B");
		FormatChecking fc = new FormatChecking(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		XmlFC result = fc.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		sig.setSignatureFormat("CAdES_BASELINE_T");
		fc = new FormatChecking(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = fc.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		sig.setSignatureFormat("CAdES_BASELINE_LT");
		fc = new FormatChecking(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = fc.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		sig.setSignatureFormat("CAdES_BASELINE_LTA");
		fc = new FormatChecking(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = fc.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		sig.setSignatureFormat("PAdES_BASELINE_B");
		fc = new FormatChecking(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = fc.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		sig.setSignatureFormat("PAdES_BASELINE_T");
		fc = new FormatChecking(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = fc.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		sig.setSignatureFormat("PAdES_BASELINE_LT");
		fc = new FormatChecking(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = fc.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		sig.setSignatureFormat("PAdES_BASELINE_LTA");
		fc = new FormatChecking(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = fc.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		sig.setSignatureFormat("XAdES_BASELINE_B");
		fc = new FormatChecking(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = fc.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

		sig.setSignatureFormat("CAdES_BASELINE_T");
		fc = new FormatChecking(new SignatureWrapper(sig), Context.COUNTER_SIGNATURE, policy);
		result = fc.execute();
		assertEquals(Indication.PASSED, result.getConclusion().getIndication());

	}

	@Test
	public void invalidFormat() throws Exception {
		XmlSignature sig = new XmlSignature();
		EtsiValidationPolicy policy = LoadPolicyUtils.loadPolicy();

		sig.setSignatureFormat("Invalid_Format");
		FormatChecking fc = new FormatChecking(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		XmlFC result = fc.execute();
		assertEquals(Indication.FAILED, result.getConclusion().getIndication());

		sig.setSignatureFormat("XAdES_BASELINE_T");
		fc = new FormatChecking(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = fc.execute();
		assertEquals(Indication.FAILED, result.getConclusion().getIndication());

		sig.setSignatureFormat("");
		fc = new FormatChecking(new SignatureWrapper(sig), Context.SIGNATURE, policy);
		result = fc.execute();
		assertEquals(Indication.FAILED, result.getConclusion().getIndication());
	}

}

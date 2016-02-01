package eu.europa.esig.dss.validation.policy.bbb;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.bbb.util.TestDiagnosticDataGenerator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.bbb.cv.CryptographicVerification;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;

public class CryptographicVerificationTest extends AbstractValidationPolicy {

	private static final Logger logger = LoggerFactory.getLogger(CryptographicVerificationTest.class);

	@Test
	public void CryptographicVerificationWithBasicDataTest() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ConstraintsParameters parameters = getConstraintsParameters();
		ValidationPolicy policy = new EtsiValidationPolicy(parameters);

		CryptographicVerification verification = new CryptographicVerification(diagnosticData.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlCV cv = verification.execute();

		for (XmlConstraint constraint : cv.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.VALID, cv.getConclusion().getIndication());
		Assert.assertEquals(3, cv.getConstraint().size());
	}

	@Test
	public void CryptographicVerificationWithSignatureNonIntactTest() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithNonIntactSignature();

		ConstraintsParameters parameters = getConstraintsParameters();
		ValidationPolicy policy = new EtsiValidationPolicy(parameters);

		CryptographicVerification verification = new CryptographicVerification(diagnosticData.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlCV cv = verification.execute();

		for (XmlConstraint constraint : cv.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, cv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CRYPTO_FAILURE, cv.getConclusion().getSubIndication());
		Assert.assertEquals(3, cv.getConstraint().size());
	}

	@Test
	public void CryptographicVerificationWithDataReferenceNonIntactTest() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticReferenceDataWithNonIntactSignature();

		ConstraintsParameters parameters = getConstraintsParameters();
		ValidationPolicy policy = new EtsiValidationPolicy(parameters);

		CryptographicVerification verification = new CryptographicVerification(diagnosticData.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlCV cv = verification.execute();

		for (XmlConstraint constraint : cv.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, cv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.HASH_FAILURE, cv.getConclusion().getSubIndication());
		Assert.assertEquals(2, cv.getConstraint().size());
	}

	@Test
	public void CryptographicVerificationWithDataReferenceNotFoundTest() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticReferenceDataWithNotFound();

		ConstraintsParameters parameters = getConstraintsParameters();
		ValidationPolicy policy = new EtsiValidationPolicy(parameters);

		CryptographicVerification verification = new CryptographicVerification(diagnosticData.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlCV cv = verification.execute();

		for (XmlConstraint constraint : cv.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, cv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, cv.getConclusion().getSubIndication());
		Assert.assertEquals(1, cv.getConstraint().size());
	}
}

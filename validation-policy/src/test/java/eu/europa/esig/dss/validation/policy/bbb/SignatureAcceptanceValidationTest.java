package eu.europa.esig.dss.validation.policy.bbb;

import java.util.Date;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.validation.policy.bbb.util.TestDiagnosticDataGenerator;
import eu.europa.esig.dss.validation.policy.bbb.util.TestPolicyGenerator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.bbb.sav.SignatureAcceptanceValidation;
import eu.europa.esig.dss.validation.wrappers.DiagnosticData;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SignatureAcceptanceValidationTest {

	private static final Logger logger = LoggerFactory.getLogger(SignatureAcceptanceValidationTest.class);

	@Test
	public void testWithBasicDataAndCertifiedRolesAsInformLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE,
				TestPolicyGenerator.generatePolicy());
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.VALID, sav.getConclusion().getIndication());
		Assert.assertEquals(12, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButCertifiedRolesAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ValidationPolicy policy = TestPolicyGenerator.generatePolicy();
		policy.getCertifiedRolesConstraint().setLevel(Level.FAIL);

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ICERRM_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(11, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButCertifiedRolesAsWarn() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ValidationPolicy policy = TestPolicyGenerator.generatePolicy();
		policy.getCertifiedRolesConstraint().setLevel(Level.WARN);

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.VALID, sav.getConclusion().getIndication());
		Assert.assertEquals(12, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButClaimedRolesAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ValidationPolicy policy = TestPolicyGenerator.generatePolicy();
		policy.getClaimedRoleConstraint().setLevel(Level.FAIL);

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ICRM_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(10, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButContentTypeAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ValidationPolicy policy = TestPolicyGenerator.generatePolicy();
		policy.getContentTypeConstraint().setLevel(Level.FAIL);

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ISQPCTP_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(3, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButContentHintsAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ValidationPolicy policy = TestPolicyGenerator.generatePolicy();
		policy.getContentHintsConstraint().setLevel(Level.FAIL);

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ISQPCHP_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(4, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButContentIdentifierAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ValidationPolicy policy = TestPolicyGenerator.generatePolicy();
		policy.getContentIdentifierConstraint().setLevel(Level.FAIL);

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ISQPCIP_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(5, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButCommitmentTypeIndicationAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ValidationPolicy policy = TestPolicyGenerator.generatePolicy();
		policy.getCommitmentTypeIndicationConstraint().setLevel(Level.FAIL);

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ISQPXTIP_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(6, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButContentTimestampAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ValidationPolicy policy = TestPolicyGenerator.generatePolicy();
		policy.getContentTimestampConstraint().setLevel(Level.FAIL);

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ISQPCTSIP_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(8, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButCounterSignatureAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ValidationPolicy policy = TestPolicyGenerator.generatePolicy();
		policy.getCounterSignatureConstraint().setLevel(Level.FAIL);

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_IUQPCSP_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(9, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataWithNoSigningTimeAndLevelFail() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateDiagnosticDataWithNoSigningDate();

		ValidationPolicy policy = TestPolicyGenerator.generatePolicy();
		policy.getSigningTimeConstraint().setLevel(Level.FAIL);

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ISQPSTP_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(2, sav.getConstraint().size());
	}

	@Test
	public void testWithCryptographicError() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateDiagnosticDataWithWrongEncriptionAlgo();

		ValidationPolicy policy = TestPolicyGenerator.generatePolicy();

		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(12, sav.getConstraint().size());
		Assert.assertEquals(4, sav.getConstraint().get(sav.getConstraint().size() - 1).getInfo().size());
	}

}

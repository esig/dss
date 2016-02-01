package eu.europa.esig.dss.validation.policy.bbb;

import java.util.Date;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.MessageTag;
import eu.europa.esig.dss.validation.policy.Context;
import eu.europa.esig.dss.validation.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.validation.policy.ValidationPolicy;
import eu.europa.esig.dss.validation.policy.bbb.util.TestDiagnosticDataGenerator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.process.bbb.sav.SignatureAcceptanceValidation;
import eu.europa.esig.dss.validation.reports.wrapper.DiagnosticData;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SignatureAcceptanceValidationTest extends AbstractValidationPolicy {

	private static final Logger logger = LoggerFactory.getLogger(SignatureAcceptanceValidationTest.class);

	@Test
	public void testWithBasicDataAndCertifiedRolesAsInformLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();
		
		ConstraintsParameters parameters = getConstraintsParameters();
		ValidationPolicy policy = new EtsiValidationPolicy(parameters);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE,
				policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.VALID, sav.getConclusion().getIndication());
	}

	@Test
	public void testWithBasicDataButCertifiedRolesAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ConstraintsParameters constraints = getConstraintsParameters();
		constraints.getSignatureConstraints().getSignedAttributes().setCertifiedRoles(createMultiValueConstraint(Level.FAIL));
		
		ValidationPolicy policy = new EtsiValidationPolicy(constraints);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ICERRM_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(2, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButCertifiedRolesAsWarn() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ConstraintsParameters constraints = getConstraintsParameters();
		constraints.getSignatureConstraints().getSignedAttributes().setCertifiedRoles(createMultiValueConstraint(Level.WARN));
		
		ValidationPolicy policy = new EtsiValidationPolicy(constraints);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.VALID, sav.getConclusion().getIndication());
	}

	@Test
	public void testWithBasicDataButClaimedRolesAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ConstraintsParameters constraints = getConstraintsParameters();
		constraints.getSignatureConstraints().getSignedAttributes().setClaimedRoles(createMultiValueConstraint(Level.FAIL));
		
		ValidationPolicy policy = new EtsiValidationPolicy(constraints);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ICRM_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(2, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButContentTypeAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ConstraintsParameters constraints = getConstraintsParameters();
		constraints.getSignatureConstraints().getSignedAttributes().setContentType(createValueConstraint(Level.FAIL));
		
		ValidationPolicy policy = new EtsiValidationPolicy(constraints);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ISQPCTP_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(2, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButContentHintsAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ConstraintsParameters constraints = getConstraintsParameters();
		constraints.getSignatureConstraints().getSignedAttributes().setContentHints(createValueConstraint(Level.FAIL));
		
		ValidationPolicy policy = new EtsiValidationPolicy(constraints);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ISQPCHP_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(2, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButContentIdentifierAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ConstraintsParameters constraints = getConstraintsParameters();
		constraints.getSignatureConstraints().getSignedAttributes().setContentIdentifier(createValueConstraint(Level.FAIL));
		
		ValidationPolicy policy = new EtsiValidationPolicy(constraints);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ISQPCIP_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(2, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButCommitmentTypeIndicationAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ConstraintsParameters constraints = getConstraintsParameters();
		constraints.getSignatureConstraints().getSignedAttributes().setCommitmentTypeIndication(createMultiValueConstraint(Level.FAIL));
		
		ValidationPolicy policy = new EtsiValidationPolicy(constraints);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ISQPXTIP_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(2, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButContentTimestampAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();

		ConstraintsParameters constraints = getConstraintsParameters();
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);
		constraints.getSignatureConstraints().getSignedAttributes().setContentTimeStamp(levelConstraint);
		
		ValidationPolicy policy = new EtsiValidationPolicy(constraints);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ISQPCTSIP_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(2, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataButCounterSignatureAsFailLevel() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();
		
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);

		ConstraintsParameters constraints = getConstraintsParameters();
		constraints.getSignatureConstraints().getUnsignedAttributes().setCounterSignature(levelConstraint);
		
		ValidationPolicy policy = new EtsiValidationPolicy(constraints);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_IUQPCSP_ANS.getMessage(), sav.getConclusion().getError().getValue());
		Assert.assertEquals(2, sav.getConstraint().size());
	}

	@Test
	public void testWithBasicDataWithNoSigningTimeAndLevelFail() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateDiagnosticDataWithNoSigningDate();
		
		LevelConstraint levelConstraint = new LevelConstraint();
		levelConstraint.setLevel(Level.FAIL);

		ConstraintsParameters constraints = getConstraintsParameters();
		constraints.getSignatureConstraints().getSignedAttributes().setSigningTime(levelConstraint);
		
		ValidationPolicy policy = new EtsiValidationPolicy(constraints);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ISQPSTP_ANS.getMessage(), sav.getConclusion().getError().getValue());
	}

	@Test
	public void testWithCryptographicError() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateDiagnosticDataWithWrongEncriptionAlgo();

		ConstraintsParameters parameters = getConstraintsParameters();
		ValidationPolicy policy = new EtsiValidationPolicy(parameters);

		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, policy);
		XmlSAV sav = validation.execute();

		for (XmlConstraint constraint : sav.getConstraint()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}

		Assert.assertEquals(Indication.INDETERMINATE, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(2, sav.getConstraint().size());
	}
}

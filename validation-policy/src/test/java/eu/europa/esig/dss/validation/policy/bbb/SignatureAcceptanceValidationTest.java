package eu.europa.esig.dss.validation.policy.bbb;

import java.util.Date;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.EN319102.bbb.sav.SignatureAcceptanceValidation;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlSAV;
import eu.europa.esig.dss.validation.policy.bbb.util.TestDiagnosticDataGenerator;
import eu.europa.esig.dss.validation.policy.bbb.util.TestPolicyGenerator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.MessageTag;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class SignatureAcceptanceValidationTest {
	
	private static final Logger logger = LoggerFactory.getLogger(SignatureAcceptanceValidationTest.class);

	@Test
	public void testWithBasicDataAndBasicPolicy() throws Exception {
		DiagnosticData data = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();
		
		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);
		
		SignatureAcceptanceValidation validation = new SignatureAcceptanceValidation(data, new Date(), data.getSignatures().get(0), Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlSAV sav = validation.execute();
		
		for(XmlConstraint constraint : sav.getConstraints()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}
		
		Assert.assertEquals(Indication.VALID, sav.getConclusion().getIndication());
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
		
		for(XmlConstraint constraint : sav.getConstraints()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}
		
		Assert.assertEquals(Indication.INVALID, sav.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, sav.getConclusion().getSubIndication());
		Assert.assertEquals(MessageTag.BBB_SAV_ICERRM_ANS.getMessage(), sav.getConclusion().getError().getValue());
	}
}

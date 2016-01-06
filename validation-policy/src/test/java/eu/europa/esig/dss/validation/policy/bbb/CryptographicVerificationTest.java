package eu.europa.esig.dss.validation.policy.bbb;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.EN319102.bbb.cv.CryptographicVerification;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.jaxb.detailedreport.XmlCV;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.validation.policy.bbb.util.TestDiagnosticDataGenerator;
import eu.europa.esig.dss.validation.policy.bbb.util.TestPolicyGenerator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class CryptographicVerificationTest {
	
	private static final Logger logger = LoggerFactory.getLogger(CryptographicVerificationTest.class);

	@Test
	public void CryptographicVerificationWithBasicDataTest() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();
		
		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);
		
		CryptographicVerification verification = new CryptographicVerification(diagnosticData.getSignatures().get(0), Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlCV xcv = verification.execute();
		
		for(XmlConstraint constraint : xcv.getConstraints()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}
		
		Assert.assertEquals(Indication.VALID, xcv.getConclusion().getIndication());
	}
	
	@Test
	public void CryptographicVerificationWithSignatureNonIntactTest() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithNonIntactSignature();
		
		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);
		
		CryptographicVerification verification = new CryptographicVerification(diagnosticData.getSignatures().get(0), Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlCV xcv = verification.execute();
		
		for(XmlConstraint constraint : xcv.getConstraints()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}
		
		Assert.assertEquals(Indication.INVALID, xcv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIG_CRYPTO_FAILURE, xcv.getConclusion().getSubIndication());
	}
	
	@Test
	public void CryptographicVerificationWithDataReferenceNonIntactTest() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticReferenceDataWithNonIntactSignature();
		
		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);
		
		CryptographicVerification verification = new CryptographicVerification(diagnosticData.getSignatures().get(0), Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlCV xcv = verification.execute();
		
		for(XmlConstraint constraint : xcv.getConstraints()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}
		
		Assert.assertEquals(Indication.INVALID, xcv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.HASH_FAILURE, xcv.getConclusion().getSubIndication());
	}
	
	@Test
	public void CryptographicVerificationWithDataReferenceNotFoundTest() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticReferenceDataWithNotFound();
		
		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);
		
		CryptographicVerification verification = new CryptographicVerification(diagnosticData.getSignatures().get(0), Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlCV xcv = verification.execute();
		
		for(XmlConstraint constraint : xcv.getConstraints()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}
		
		Assert.assertEquals(Indication.INDETERMINATE, xcv.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, xcv.getConclusion().getSubIndication());
	}
}

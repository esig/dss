package eu.europa.esig.dss.validation.policy.bbb;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.EN319102.bbb.isc.IdentificationOfTheSigningCertificate;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlISC;
import eu.europa.esig.dss.validation.policy.bbb.util.TestDiagnosticDataGenerator;
import eu.europa.esig.dss.validation.policy.bbb.util.TestPolicyGenerator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.policy.rules.SubIndication;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class IdentificationOfTheSigningCertificateTest {

	private static final Logger logger = LoggerFactory.getLogger(IdentificationOfTheSigningCertificateTest.class);
			
	@Test
	public void testWithBasicData() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();
		
		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);
		
		IdentificationOfTheSigningCertificate verification = new IdentificationOfTheSigningCertificate(diagnosticData, diagnosticData.getSignatures().get(0), Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlISC isc = verification.execute();
		
		for(XmlConstraint constraint : isc.getConstraints()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}
		
		Assert.assertEquals(Indication.VALID, isc.getConclusion().getIndication());
		Assert.assertEquals(6, isc.getConstraints().size());
	}
	
	@Test
	public void testWithDigestNotPresent() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateDiagnosticDataWithDigestValueOfTheCertificateNotPresent();
		
		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);
		
		IdentificationOfTheSigningCertificate verification = new IdentificationOfTheSigningCertificate(diagnosticData, diagnosticData.getSignatures().get(0), Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlISC isc = verification.execute();
		
		for(XmlConstraint constraint : isc.getConstraints()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}
		
		Assert.assertEquals(Indication.INVALID, isc.getConclusion().getIndication());
		Assert.assertEquals(SubIndication.FORMAT_FAILURE, isc.getConclusion().getSubIndication());
		Assert.assertEquals(4, isc.getConstraints().size());
	}
}

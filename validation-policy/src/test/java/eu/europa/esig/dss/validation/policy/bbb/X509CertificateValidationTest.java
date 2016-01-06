package eu.europa.esig.dss.validation.policy.bbb;

import java.util.Date;

import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.esig.dss.EN319102.bbb.xcv.X509CertificateValidation;
import eu.europa.esig.dss.EN319102.policy.ValidationPolicy.Context;
import eu.europa.esig.dss.jaxb.detailedreport.XmlConstraint;
import eu.europa.esig.dss.jaxb.detailedreport.XmlXCV;
import eu.europa.esig.dss.validation.policy.bbb.util.TestDiagnosticDataGenerator;
import eu.europa.esig.dss.validation.policy.bbb.util.TestPolicyGenerator;
import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.report.DiagnosticData;
import eu.europa.esig.jaxb.policy.Level;
import eu.europa.esig.jaxb.policy.LevelConstraint;

public class X509CertificateValidationTest {
	
	private static final Logger logger = LoggerFactory.getLogger(X509CertificateValidationTest.class);

	@Test
	public void test() throws Exception {
		DiagnosticData diagnosticData = TestDiagnosticDataGenerator.generateSimpleDiagnosticData();
		
		LevelConstraint failLevel = new LevelConstraint();
		failLevel.setLevel(Level.FAIL);
		
		X509CertificateValidation verification = new X509CertificateValidation(diagnosticData, diagnosticData.getUsedCertificates().get(0), new Date(), Context.SIGNATURE, TestPolicyGenerator.generatePolicy());
		XmlXCV xcv = verification.execute();
		
		for(XmlConstraint constraint : xcv.getConstraints()) {
			logger.info(constraint.getName().getValue() + " : " + constraint.getStatus());
		}
		
		Assert.assertEquals(Indication.VALID, xcv.getConclusion().getIndication());
	}
}

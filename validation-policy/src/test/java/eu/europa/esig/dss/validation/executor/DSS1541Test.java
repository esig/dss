package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertEquals;

import java.util.List;

import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

import eu.europa.esig.dss.validation.policy.rules.Indication;
import eu.europa.esig.dss.validation.reports.SimpleReport;
import eu.europa.esig.jaxb.policy.Algo;
import eu.europa.esig.jaxb.policy.BasicSignatureConstraints;
import eu.europa.esig.jaxb.policy.CertificateConstraints;
import eu.europa.esig.jaxb.policy.ConstraintsParameters;
import eu.europa.esig.jaxb.policy.CryptographicConstraint;
import eu.europa.esig.jaxb.policy.SignatureConstraints;

public class DSS1541Test extends AbstractCryptographicConstraintsTest {
	
	@Before
	public void initializeDiagnosticData() throws Exception {
		initializeExecutor("src/test/resources/DSS-1541/diag-data.xml");
	}
	
	@Ignore
	@Test
	public void signingCertificateCryptographicConstrainsTest() throws Exception {
		
		SimpleReport simpleReport = null;
		
		validationPolicyFile = "src/test/resources/policy/all-constraint-specified-policy.xml";
		loadConstraintsParameters();
		setValidationPolicy(constraintsParameters);
		simpleReport = createSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		

		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CertificateConstraints signingCertificateConstraints = getSigningCertificateConstraints(constraintsParameters);
		CryptographicConstraint signingCertCryptographicConstraint = signingCertificateConstraints.getCryptographic();
		List<Algo> listEncryptionAlgo = signingCertCryptographicConstraint.getAcceptableEncryptionAlgo().getAlgo();
		removeAlgorithm(listEncryptionAlgo, ALGORITHM_RSA);
		
		signingCertificateConstraints.setCryptographic(signingCertCryptographicConstraint);
		setSigningCertificateConstraints(constraintsParameters, signingCertCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		simpleReport = createSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
	}

}

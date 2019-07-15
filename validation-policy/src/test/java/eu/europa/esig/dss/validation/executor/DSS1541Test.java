package eu.europa.esig.dss.validation.executor;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.util.List;

import org.junit.Test;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.TimestampConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;

public class DSS1541Test extends AbstractCryptographicConstraintsTest {
	
	@Test
	public void signingCertificateWrongCryptographicConstrainsTest() throws Exception {
		
		initializeExecutor("src/test/resources/universign.xml");
		validationPolicyFile = new File("src/test/resources/policy/all-constraint-specified-policy.xml");
		
		SimpleReport simpleReport = null;
		
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		setValidationPolicy(constraintsParameters);
		simpleReport = createSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
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
	
	@Test
	public void caCertificateWrongCryptographicConstrainsTest() throws Exception {
		
		initializeExecutor("src/test/resources/universign.xml");
		validationPolicyFile = new File("src/test/resources/policy/all-constraint-specified-policy.xml");
		
		SimpleReport simpleReport = null;
		
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		setValidationPolicy(constraintsParameters);
		simpleReport = createSimpleReport();
		// good case
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		

		// force past validation, but with a valid timestamp on the RSA algorithm expiration date 
		CryptographicConstraint sigCryptographicConstraint = getSignatureCryptographicConstraint(constraintsParameters);
		setAlgoExpirationDate(sigCryptographicConstraint, ALGORITHM_SHA256, "2018-01-01");
		setSignatureCryptographicConstraint(constraintsParameters, sigCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		simpleReport = createSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		

		// remove algorithm for CA certificates to invalidate the chain
		CertificateConstraints caCertificateConstraints = getCACertificateConstraints(constraintsParameters);
		CryptographicConstraint caCertCryptographicConstraint = caCertificateConstraints.getCryptographic();
		List<Algo> listEncryptionAlgo = caCertCryptographicConstraint.getAcceptableEncryptionAlgo().getAlgo();
		removeAlgorithm(listEncryptionAlgo, ALGORITHM_RSA);
		caCertificateConstraints.setCryptographic(caCertCryptographicConstraint);
		setCACertificateConstraints(constraintsParameters, caCertCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		simpleReport = createSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
	}
	
	@Test
	public void timestampConstraintsTest() throws Exception {
		
		initializeExecutor("src/test/resources/passed_out_of_bounds_with_timestamps.xml");
		validationPolicyFile = new File("src/test/resources/policy/all-constraint-specified-policy.xml");
		
		SimpleReport simpleReport = null;
		
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		setValidationPolicy(constraintsParameters);
		simpleReport = createSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		TimestampConstraints timestampConstraints = constraintsParameters.getTimestamp();
		BasicSignatureConstraints basicSignatureConstraints = timestampConstraints.getBasicSignatureConstraints();
		CertificateConstraints signCertConstraints = basicSignatureConstraints.getSigningCertificate();
		CryptographicConstraint cryptographicConstraint = signCertConstraints.getCryptographic();
		
		List<Algo> listEncryptionAlgo = cryptographicConstraint.getAcceptableEncryptionAlgo().getAlgo();
		removeAlgorithm(listEncryptionAlgo, ALGORITHM_RSA);
		List<Algo> listHashAlgo = cryptographicConstraint.getAcceptableDigestAlgo().getAlgo();
		removeAlgorithm(listHashAlgo, ALGORITHM_SHA256);
		
		signCertConstraints.setCryptographic(cryptographicConstraint);
		basicSignatureConstraints.setSigningCertificate(signCertConstraints);
		timestampConstraints.setBasicSignatureConstraints(basicSignatureConstraints);
		constraintsParameters.setTimestamp(timestampConstraints);
		setValidationPolicy(constraintsParameters);
		simpleReport = createSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
	}
	
}

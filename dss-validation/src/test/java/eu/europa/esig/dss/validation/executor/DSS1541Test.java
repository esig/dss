/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * 
 * This file is part of the "DSS - Digital Signature Services" project.
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.executor;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.TimestampConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DSS1541Test extends AbstractCryptographicConstraintsTest {
	
	@Test
	public void signingCertificateWrongCryptographicConstrainsTest() throws Exception {
		
		initializeExecutor("src/test/resources/universign.xml");
		validationPolicyFile = new File("src/test/resources/policy/all-constraint-specified-policy.xml");
		
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		CertificateConstraints signingCertificateConstraints = getSigningCertificateConstraints(constraintsParameters);
		CryptographicConstraint signingCertCryptographicConstraint = signingCertificateConstraints.getCryptographic();
		List<Algo> listEncryptionAlgo = signingCertCryptographicConstraint.getAcceptableDigestAlgo().getAlgos();
		removeAlgo(listEncryptionAlgo, ALGORITHM_SHA256, 0);
		
		signingCertificateConstraints.setCryptographic(signingCertCryptographicConstraint);
		setSigningCertificateConstraints(constraintsParameters, signingCertCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		simpleReport = createSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
	}
	
	@Test
	public void caCertificateWrongCryptographicConstrainsTest() throws Exception {
		
		initializeExecutor("src/test/resources/universign.xml");
		validationPolicyFile = new File("src/test/resources/policy/all-constraint-specified-policy.xml");
		
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		// good case
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		// force past validation, but with a valid timestamp on the RSA algorithm expiration date 
		CryptographicConstraint sigCryptographicConstraint = getSignatureCryptographicConstraint(constraintsParameters);
		setAlgoExpDate(sigCryptographicConstraint, ALGORITHM_SHA256, 0, "2018-01-01");
		setSignatureCryptographicConstraint(constraintsParameters, sigCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		simpleReport = createSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
	}
	
	@Test
	public void timestampConstraintsTest() throws Exception {
		
		initializeExecutor("src/test/resources/passed_out_of_bounds_with_timestamps.xml");
		validationPolicyFile = new File("src/test/resources/policy/all-constraint-specified-policy.xml");
		
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		
		TimestampConstraints timestampConstraints = constraintsParameters.getTimestamp();
		BasicSignatureConstraints basicSignatureConstraints = timestampConstraints.getBasicSignatureConstraints();
		CertificateConstraints signCertConstraints = basicSignatureConstraints.getSigningCertificate();
		CryptographicConstraint cryptographicConstraint = signCertConstraints.getCryptographic();
		
		List<Algo> listEncryptionAlgo = cryptographicConstraint.getAcceptableEncryptionAlgo().getAlgos();
		removeAlgo(listEncryptionAlgo, ALGORITHM_RSA, 0);
		List<Algo> listHashAlgo = cryptographicConstraint.getAcceptableDigestAlgo().getAlgos();
		removeAlgo(listHashAlgo, ALGORITHM_SHA256, 0);
		
		signCertConstraints.setCryptographic(cryptographicConstraint);
		basicSignatureConstraints.setSigningCertificate(signCertConstraints);
		timestampConstraints.setBasicSignatureConstraints(basicSignatureConstraints);
		constraintsParameters.setTimestamp(timestampConstraints);
		setValidationPolicy(constraintsParameters);
		simpleReport = createSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.OUT_OF_BOUNDS_NOT_REVOKED, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
		
	}
	
}

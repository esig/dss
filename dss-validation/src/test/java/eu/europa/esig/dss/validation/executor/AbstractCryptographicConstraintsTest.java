/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.validation.executor;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.policy.EtsiValidationPolicy;
import eu.europa.esig.dss.policy.ValidationPolicy;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.BasicSignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.CertificateConstraints;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.RevocationConstraints;
import eu.europa.esig.dss.policy.jaxb.SignatureConstraints;
import eu.europa.esig.dss.policy.jaxb.TimestampConstraints;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.reports.Reports;

import java.io.File;
import java.util.Iterator;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public abstract class AbstractCryptographicConstraintsTest extends AbstractTestValidationExecutor {

	protected ConstraintsParameters constraintsParameters = null;
	protected DefaultSignatureProcessExecutor executor = null;
	protected ValidationPolicy validationPolicy = null;

	protected static final String ALGORITHM_DSA = "DSA";
	protected static final String ALGORITHM_RSA = "RSA";
	protected static final String ALGORITHM_RSASSA_PSS = "RSASSA-PSS";
	protected static final String ALGORITHM_SHA1 = "SHA1";
	protected static final String ALGORITHM_SHA256 = "SHA256";
	
	protected File validationPolicyFile = null;
	
	protected XmlDiagnosticData initializeExecutor(String diagnosticDataFile) throws Exception {
		XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File(diagnosticDataFile));
		assertNotNull(diagnosticData);

		executor = new DefaultSignatureProcessExecutor();
		executor.setDiagnosticData(diagnosticData);
		executor.setCurrentTime(diagnosticData.getValidationDate());
		return diagnosticData;
	}

	protected ConstraintsParameters loadConstraintsParameters() throws Exception {
		ConstraintsParameters constraintsParameters = getConstraintsParameters(validationPolicyFile);
		this.constraintsParameters = constraintsParameters;
		return constraintsParameters;
	}
	
	protected void setValidationPolicy(ConstraintsParameters constraintsParameters) {
		validationPolicy = new EtsiValidationPolicy(constraintsParameters);
	}
	
	protected Reports createReports() {
		executor.setValidationPolicy(validationPolicy);
		return executor.execute();
	}
	
	protected CryptographicConstraint getSignatureCryptographicConstraint(ConstraintsParameters constraintsParameters) {
		SignatureConstraints sigConstraint = constraintsParameters.getSignatureConstraints();
		return sigConstraint.getBasicSignatureConstraints().getCryptographic();
	}
	
	protected void setSignatureCryptographicConstraint(ConstraintsParameters constraintsParameters, CryptographicConstraint cryptographicConstraint) {
		SignatureConstraints sigConstraint = constraintsParameters.getSignatureConstraints();
		BasicSignatureConstraints basicSignatureConstraints = sigConstraint.getBasicSignatureConstraints();
		basicSignatureConstraints.setCryptographic(cryptographicConstraint);
		sigConstraint.setBasicSignatureConstraints(basicSignatureConstraints);
		constraintsParameters.setSignatureConstraints(sigConstraint);
	}
	
	protected CertificateConstraints getSigningCertificateConstraints(ConstraintsParameters constraintsParameters) {
		return constraintsParameters.getSignatureConstraints().getBasicSignatureConstraints().getSigningCertificate();
	}
	
	protected void setSigningCertificateConstraints(ConstraintsParameters constraintsParameters, CryptographicConstraint cryptographicConstraint) {
		SignatureConstraints signatureConstraints = constraintsParameters.getSignatureConstraints();
		BasicSignatureConstraints basicSignatureConstraints = signatureConstraints.getBasicSignatureConstraints();
		CertificateConstraints certificateConstraints = basicSignatureConstraints.getSigningCertificate();
		certificateConstraints.setCryptographic(cryptographicConstraint);
		basicSignatureConstraints.setSigningCertificate(certificateConstraints);
		signatureConstraints.setBasicSignatureConstraints(basicSignatureConstraints);
	}
	
	protected CertificateConstraints getCACertificateConstraints(ConstraintsParameters constraintsParameters) {
		return constraintsParameters.getSignatureConstraints().getBasicSignatureConstraints().getCACertificate();
	}
	
	protected void setCACertificateConstraints(ConstraintsParameters constraintsParameters, CryptographicConstraint cryptographicConstraint) {
		SignatureConstraints signatureConstraints = constraintsParameters.getSignatureConstraints();
		BasicSignatureConstraints basicSignatureConstraints = signatureConstraints.getBasicSignatureConstraints();
		CertificateConstraints certificateConstraints = basicSignatureConstraints.getCACertificate();
		certificateConstraints.setCryptographic(cryptographicConstraint);
		basicSignatureConstraints.setCACertificate(certificateConstraints);
		signatureConstraints.setBasicSignatureConstraints(basicSignatureConstraints);
	}
	
	protected CryptographicConstraint getRevocationCryptographicConstraint(ConstraintsParameters constraintsParameters) {
		RevocationConstraints revocationConstraints = constraintsParameters.getRevocation();
		return revocationConstraints.getBasicSignatureConstraints().getCryptographic();
	}
	
	protected RevocationConstraints setRevocationCryptographicConstraint(ConstraintsParameters constraintsParameters, CryptographicConstraint cryptographicConstraint) {
		RevocationConstraints revocationConstraints = constraintsParameters.getRevocation();
		BasicSignatureConstraints basicSignatureConstraints = revocationConstraints.getBasicSignatureConstraints();
		basicSignatureConstraints.setCryptographic(cryptographicConstraint);
		revocationConstraints.setBasicSignatureConstraints(basicSignatureConstraints);
		constraintsParameters.setRevocation(revocationConstraints);
		return revocationConstraints;
	}
	
	protected CryptographicConstraint getTimestampCryptographicConstraint(ConstraintsParameters constraintsParameters) {
		TimestampConstraints timestampConstraints = constraintsParameters.getTimestamp();
		return timestampConstraints.getBasicSignatureConstraints().getCryptographic();
	}
	
	protected TimestampConstraints setTimestampCryptographicConstraints(ConstraintsParameters constraintsParameters, CryptographicConstraint cryptographicConstraint) {
		TimestampConstraints timestampConstraints = constraintsParameters.getTimestamp();
		BasicSignatureConstraints basicSignatureConstraints = timestampConstraints.getBasicSignatureConstraints();
		basicSignatureConstraints.setCryptographic(cryptographicConstraint);
		timestampConstraints.setBasicSignatureConstraints(basicSignatureConstraints);
		constraintsParameters.setTimestamp(timestampConstraints);
		return timestampConstraints;
	}
	
	protected SimpleReport createSimpleReport() {
		Reports reports = createReports();
		return reports.getSimpleReport();
	}
	
	protected DetailedReport createDetailedReport() {
		Reports reports = createReports();
		return reports.getDetailedReport();
	}
	
	protected void setAlgoExpDate(CryptographicConstraint defaultCryptographicConstraint, String algorithm, Integer keySize, String date) {
		if (keySize == 0) {
			setDigestAlgoExpirationDate(defaultCryptographicConstraint, algorithm, date);
		} else {
			setAlgoExpirationDate(defaultCryptographicConstraint, algorithm, date, keySize);
		}
	}
	
	private void setAlgoExpirationDate(CryptographicConstraint cryptographicConstraint, String algorithmName, String expirationDate, Integer keySize) {
		AlgoExpirationDate algoExpirationDate = cryptographicConstraint.getAlgoExpirationDate();
		List<Algo> algorithms = algoExpirationDate.getAlgos();
		boolean listContainsAlgorithms = false;
		for (Algo algorithm : algorithms) {
			if (algorithm.getValue().equals(algorithmName) && algorithm.getSize().equals(keySize)) {
				algorithm.setDate(expirationDate);
				listContainsAlgorithms = true;
			}
		}
		if (!listContainsAlgorithms) {
			algorithms.add(createAlgo(algorithmName, keySize, expirationDate));
		}
	}
	
	private void setDigestAlgoExpirationDate(CryptographicConstraint cryptographicConstraint, String algorithmName, String expirationDate) {
		AlgoExpirationDate algoExpirationDate = cryptographicConstraint.getAlgoExpirationDate();
		List<Algo> algorithms = algoExpirationDate.getAlgos();
		boolean listContainsAlgorithms = false;
		for (Algo algorithm : algorithms) {
			if (algorithm.getValue().equals(algorithmName)) {
				algorithm.setDate(expirationDate);
				listContainsAlgorithms = true;
			}
		}
		if (!listContainsAlgorithms) {
			algorithms.add(createAlgo(algorithmName, 0, expirationDate));
		}
	}
	
	protected void removeAlgo(List<Algo> algorithms, String algorithm, Integer keySize) {
		if (keySize == 0) {
			removeDigestAlgorithm(algorithms, algorithm);
		} else {
			removeEncryptionAlgorithm(algorithms, algorithm, keySize);
		}
	}
	
	private void removeDigestAlgorithm(List<Algo> algorithms, String algorithmName) {
		Iterator<Algo> iterator = algorithms.iterator();
		while (iterator.hasNext()) {
			Algo algo = iterator.next();
			if (algo.getValue().equals(algorithmName)) {
				iterator.remove();
			}
		}
	}
	
	private void removeEncryptionAlgorithm(List<Algo> algorithms, String algorithmName, Integer keySize) {
		Iterator<Algo> iterator = algorithms.iterator();
		while (iterator.hasNext()) {
			Algo algo = iterator.next();
			if (algo.getValue().equals(algorithmName) && algo.getSize().equals(keySize)) {
				iterator.remove();
			}
		}
	}
	
	protected void setAlgorithmSize(List<Algo> algorithms, String algorithm, Integer size) {
		for (Algo algo : algorithms) {
			if (algo.getValue().equals(algorithm)) {
				algo.setSize(size);
				return;
			}
		}
	}

	protected Algo createAlgo(String algoName) {
		return createAlgo(algoName, 0, null);
	}

	protected Algo createAlgo(String algoName, int keySize) {
		return createAlgo(algoName, keySize, null);
	}

	protected Algo createAlgo(String algoName, int keySize, String expirationDate) {
		Algo algo = new Algo();
		algo.setValue(algoName);
		if (keySize != 0) {
			algo.setSize(keySize);
		}
		if (expirationDate != null) {
			algo.setDate(expirationDate);
		}
		return algo;
	}

}

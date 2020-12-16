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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.List;
import java.util.Locale;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.detailedreport.jaxb.XmlBasicBuildingBlocks;
import eu.europa.esig.dss.detailedreport.jaxb.XmlName;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.i18n.I18nProvider;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.policy.jaxb.Algo;
import eu.europa.esig.dss.policy.jaxb.AlgoExpirationDate;
import eu.europa.esig.dss.policy.jaxb.ConstraintsParameters;
import eu.europa.esig.dss.policy.jaxb.CryptographicConstraint;
import eu.europa.esig.dss.policy.jaxb.Level;
import eu.europa.esig.dss.policy.jaxb.ListAlgo;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.reports.Reports;

public class CustomCryptographicConstraintsTest extends AbstractCryptographicConstraintsTest {
	
	private static I18nProvider i18nProvider;
	
	@BeforeAll
	public static void init() {
		i18nProvider = new I18nProvider(Locale.getDefault());
	}

	/**
	 * Test for signature using SHA256 as the Digest algorithm and RSA 2048 as the Encryption Algorithm
	 * Validation date is set on 2018-02-06T09:39:33
	 */
	@Test
	public void defaultOnlyCryptographicConstraintTest() throws Exception {
		
		initializeExecutor("src/test/resources/universign.xml");
		validationPolicyFile = new File("src/test/resources/policy/default-only-constraint-policy.xml");
		
		Indication result = null;
		DetailedReport detailedReport = null;
		XmlBasicBuildingBlocks revocationBasicBuildingBlock = null;
		
		result = defaultConstraintValidationDateIsBeforeExpirationDateTest(ALGORITHM_SHA256, 0);
		assertEquals(Indication.TOTAL_PASSED, result);
		checkErrorMessageAbsence(MessageTag.ASCCM_AR_ANS_ANR);
		
		result = defaultConstraintAlgorithmExpiredTest(ALGORITHM_SHA256, 0);
		assertEquals(Indication.INDETERMINATE, result);
		
		result = defaultConstraintSetLevelForPreviousValidationPolicy(Level.WARN);
		assertEquals(Indication.TOTAL_PASSED, result);
		checkErrorMessagePresence(i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA256, MessageTag.ACCM_POS_SIG_SIG));
		
		result = defaultConstraintAlgorithmExpiredTest(ALGORITHM_SHA1, 0); // some other algorithm is expired
		assertEquals(Indication.TOTAL_PASSED, result);
		
		result = defaultConstraintAlgorithmExpirationDateIsNotDefined(ALGORITHM_RSA, 2048);
		assertEquals(Indication.TOTAL_PASSED, result);

		result = defaultConstraintSetLevelForPreviousValidationPolicy(Level.WARN);
		assertEquals(Indication.TOTAL_PASSED, result);
		
		result = defaultConstraintAlgorithmExpirationDateIsNotDefined(ALGORITHM_RSA, 4096); // some other algorithm is expired
		assertEquals(Indication.TOTAL_PASSED, result);
		checkErrorMessageAbsence(MessageTag.ASCCM_AR_ANS_AEDND);
		
		result = defaultConstraintAcceptableDigestAlgorithmIsNotDefined(ALGORITHM_SHA256, 0);
		assertEquals(Indication.INDETERMINATE, result);
		detailedReport = createDetailedReport();
		revocationBasicBuildingBlock = detailedReport.getBasicBuildingBlockById(detailedReport.getRevocationIds().get(0));
		assertEquals(Indication.INDETERMINATE, revocationBasicBuildingBlock.getSAV().getConclusion().getIndication());
		assertEquals(Indication.INDETERMINATE, detailedReport.getTimestampValidationIndication(detailedReport.getTimestampIds().get(0)));
		checkRevocationErrorPresence(detailedReport, MessageTag.ASCCM_DAA_ANS, true);
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_DAA_ANS, true);

		result = defaultConstraintSetLevelForPreviousValidationPolicy(Level.WARN);
		assertEquals(Indication.TOTAL_PASSED, result);
		checkErrorMessagePresence(i18nProvider.getMessage(MessageTag.ASCCM_DAA_ANS, DigestAlgorithm.SHA256, MessageTag.ACCM_POS_SIG_SIG));
		
		result = defaultConstraintAcceptableDigestAlgorithmIsNotDefined(ALGORITHM_SHA1, 0); // some other algorithm is not defined
		assertEquals(Indication.TOTAL_PASSED, result);
		detailedReport = createDetailedReport();
		checkErrorMessageAbsence(MessageTag.ASCCM_DAA_ANS);
		revocationBasicBuildingBlock = detailedReport.getBasicBuildingBlockById(detailedReport.getRevocationIds().get(0));
		assertEquals(Indication.PASSED, revocationBasicBuildingBlock.getSAV().getConclusion().getIndication());
		assertEquals(Indication.PASSED, detailedReport.getTimestampValidationIndication(detailedReport.getTimestampIds().get(0)));
		checkRevocationErrorPresence(detailedReport, MessageTag.ASCCM_DAA_ANS, false);
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_DAA_ANS, false);
		
		result = defaultConstraintAcceptableEncryptionAlgorithmIsNotDefined(ALGORITHM_RSA, 0);
		assertEquals(Indication.INDETERMINATE, result);

		result = defaultConstraintSetLevelForPreviousValidationPolicy(Level.WARN);
		assertEquals(Indication.TOTAL_PASSED, result);
		checkErrorMessagePresence(i18nProvider.getMessage(MessageTag.ASCCM_EAA_ANS, EncryptionAlgorithm.RSA, MessageTag.ACCM_POS_SIG_SIG));
		
		result = defaultConstraintAcceptableEncryptionAlgorithmIsNotDefined(ALGORITHM_DSA, 0); // some other algorithm is not defined
		assertEquals(Indication.TOTAL_PASSED, result);
		checkErrorMessageAbsence(MessageTag.ASCCM_EAA_ANS);
		
		result = defaultConstraintLargeMiniPublicKeySize(ALGORITHM_RSA);
		assertEquals(Indication.INDETERMINATE, result);

		result = defaultConstraintSetLevelForPreviousValidationPolicy(Level.WARN);
		assertEquals(Indication.TOTAL_PASSED, result);
		checkErrorMessagePresence(i18nProvider.getMessage(MessageTag.ASCCM_APKSA_ANS, EncryptionAlgorithm.RSA, "2048", MessageTag.ACCM_POS_SIG_SIG));
		
		result = defaultConstraintLargeMiniPublicKeySize(ALGORITHM_DSA); // some other algorithm is changed
		assertEquals(Indication.TOTAL_PASSED, result);
		
	}

	@Test
	public void overrideDefaultCryptographicConstraintTest() throws Exception {
		
		initializeExecutor("src/test/resources/universign.xml");
		validationPolicyFile = new File("src/test/resources/policy/all-constraint-specified-policy.xml");
		
		Indication result = null;
		DetailedReport detailedReport = null;
		
		// tests change only default constraints
		result = defaultConstraintValidationDateIsBeforeExpirationDateTest(ALGORITHM_SHA256, 0);
		assertEquals(Indication.TOTAL_PASSED, result);
		
		result = defaultConstraintAlgorithmExpiredTest(ALGORITHM_SHA256, 0);
		assertEquals(Indication.TOTAL_PASSED, result);
		
		result = defaultConstraintAlgorithmExpirationDateIsNotDefined(ALGORITHM_SHA256, 0);
		assertEquals(Indication.TOTAL_PASSED, result);
		
		result = defaultConstraintAlgorithmExpirationDateIsNotDefined(ALGORITHM_RSA, 2048);
		assertEquals(Indication.TOTAL_PASSED, result);
		
		result = defaultConstraintAcceptableDigestAlgorithmIsNotDefined(ALGORITHM_SHA256, 0);
		assertEquals(Indication.TOTAL_PASSED, result);
		
		result = defaultConstraintAcceptableEncryptionAlgorithmIsNotDefined(ALGORITHM_RSA, 0);
		assertEquals(Indication.TOTAL_PASSED, result);
		
		result = defaultConstraintLargeMiniPublicKeySize(ALGORITHM_RSA);
		assertEquals(Indication.TOTAL_PASSED, result);
		
		// tests change main Signature constraints
		result = signatureConstraintAlgorithmExpired(ALGORITHM_SHA256, "2015-01-01", 0);
		assertEquals(Indication.INDETERMINATE, result);
		
		result = signatureConstraintAlgorithmExpired(ALGORITHM_SHA1, "2015-01-01", 0); // some other algorithm is changed
		assertEquals(Indication.TOTAL_PASSED, result);
		
		result = signatureConstraintAlgorithmExpirationDateIsNotDefined(ALGORITHM_SHA256, 0);
		assertEquals(Indication.INDETERMINATE, result);
		
		result = signatureConstraintAlgorithmExpirationDateIsNotDefined(ALGORITHM_SHA1, 0); // some other algorithm is changed
		assertEquals(Indication.TOTAL_PASSED, result);
		
		result = signatureConstraintAlgorithmExpirationDateIsNotDefined(ALGORITHM_RSA, 2048);
		assertEquals(Indication.TOTAL_PASSED, result);
		
		result = signatureConstraintAlgorithmExpirationDateIsNotDefined(ALGORITHM_RSA, 4096); // some other algorithm is changed
		assertEquals(Indication.TOTAL_PASSED, result);
		
		result = signatureConstraintAcceptableDigestAlgorithmIsNotDefined(ALGORITHM_SHA256, 0);
		assertEquals(Indication.INDETERMINATE, result);
		
		result = signatureConstraintAcceptableDigestAlgorithmIsNotDefined(ALGORITHM_SHA1, 0); // some other algorithm is changed
		assertEquals(Indication.TOTAL_PASSED, result);
		
		result = signatureConstraintAcceptableEncriptionAlgorithmIsNotDefined(ALGORITHM_RSA, 0);
		assertEquals(Indication.INDETERMINATE, result);
		
		result = signatureConstraintAcceptableEncriptionAlgorithmIsNotDefined(ALGORITHM_DSA, 0); // some other algorithm is changed
		assertEquals(Indication.TOTAL_PASSED, result);
		
		result = signatureConstraintLargeMiniPublicKeySize(ALGORITHM_RSA);
		assertEquals(Indication.INDETERMINATE, result);
		
		result = signatureConstraintLargeMiniPublicKeySize(ALGORITHM_DSA); // some other algorithm is changed
		assertEquals(Indication.TOTAL_PASSED, result);
		
		detailedReport = createDetailedReport();
		XmlBasicBuildingBlocks revocationBasicBuildingBlock = detailedReport.getBasicBuildingBlockById(detailedReport.getRevocationIds().get(0));
		assertEquals(Indication.PASSED, revocationBasicBuildingBlock.getSAV().getConclusion().getIndication());
		checkErrorMessageAbsence(MessageTag.ASCCM_DAA_ANS);
		
		result = revocationConstraintAcceptableEncryptionAlgorithmIsNotDefined(ALGORITHM_RSA, 0);
		detailedReport = createDetailedReport();
		revocationBasicBuildingBlock = detailedReport.getBasicBuildingBlockById(detailedReport.getRevocationIds().get(0));
		assertEquals(Indication.INDETERMINATE, revocationBasicBuildingBlock.getSAV().getConclusion().getIndication());
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, revocationBasicBuildingBlock.getSAV().getConclusion().getSubIndication());
		
		// Revocation data tests
		result = revocationConstraintAcceptableDigestAlgorithmIsNotDefined(ALGORITHM_SHA256, 0);

		detailedReport = createDetailedReport();
		revocationBasicBuildingBlock = detailedReport.getBasicBuildingBlockById(detailedReport.getRevocationIds().get(0));
		assertEquals(Indication.INDETERMINATE, revocationBasicBuildingBlock.getSAV().getConclusion().getIndication());
		assertEquals(Indication.INDETERMINATE, detailedReport.getTimestampValidationIndication(detailedReport.getTimestampIds().get(0)));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, detailedReport.getTimestampValidationSubIndication(detailedReport.getTimestampIds().get(0)));
		checkRevocationErrorPresence(detailedReport, MessageTag.ASCCM_DAA_ANS, true);
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_DAA_ANS, false);
		
		// Timestamp tests
		result = timestampConstraintAcceptableDigestAlgorithmIsNotDefined(ALGORITHM_SHA256, 0);
		detailedReport = createDetailedReport();
		revocationBasicBuildingBlock = detailedReport.getBasicBuildingBlockById(detailedReport.getRevocationIds().get(0));
		assertEquals(Indication.PASSED, revocationBasicBuildingBlock.getSAV().getConclusion().getIndication());
		assertEquals(Indication.INDETERMINATE, detailedReport.getTimestampValidationIndication(detailedReport.getTimestampIds().get(0)));
		checkRevocationErrorPresence(detailedReport, MessageTag.ASCCM_DAA_ANS, false);
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_DAA_ANS, true);
		
	}
	
	@Test
	public void noCryptoPolicyTest() throws Exception {
		initializeExecutor("src/test/resources/universign.xml");
		validationPolicyFile = new File("src/test/resources/policy/no-crypto-constraint-policy.xml");
		
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		Indication result = simpleReport.getIndication(simpleReport.getFirstSignatureId());
		assertEquals(Indication.TOTAL_PASSED, result);
	}
	
	@Test
	public void failTimestampDelayTest() throws Exception {
		initializeExecutor("src/test/resources/universign.xml");
		validationPolicyFile = new File("src/test/resources/policy/no-crypto-constraint-policy.xml");
		
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		constraintsParameters.getTimestamp().getTimestampDelay().setLevel(Level.FAIL);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
		assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
	}

	@Test
	public void pastSignatureValidationTest() throws Exception {
		
		initializeExecutor("src/test/resources/diag_data_pastSigValidation.xml");
		validationPolicyFile = new File("src/test/resources/policy/all-constraint-specified-policy.xml");
		
		Indication result = null;
		DetailedReport detailedReport = null;

		result = signatureConstraintAlgorithmExpired(ALGORITHM_SHA256, "2020-01-01", 0);
		assertEquals(Indication.TOTAL_PASSED, result);
		detailedReport = createDetailedReport();
		checkBasicSignatureErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, false);
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, false);
		
		result = signatureConstraintAlgorithmExpired(ALGORITHM_SHA256, "2019-01-01", 0);
		assertEquals(Indication.TOTAL_PASSED, result);
		detailedReport = createDetailedReport();
		checkBasicSignatureErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, true); // PSV is not executed
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, false);
		
		result = signatureConstraintAlgorithmExpired(ALGORITHM_SHA256, "2018-01-01", 0);
		assertEquals(Indication.INDETERMINATE, result);
		detailedReport = createDetailedReport();
		checkBasicSignatureErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, true);
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, false);
		
		result = signatureConstraintAlgorithmExpired(ALGORITHM_SHA1, "2018-01-01", 0);
		assertEquals(Indication.TOTAL_PASSED, result);
		detailedReport = createDetailedReport();
		checkBasicSignatureErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, false);
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, false);
		
		result = signatureConstraintAlgorithmExpired(ALGORITHM_RSA, "2020-01-01", 0);
		assertEquals(Indication.TOTAL_PASSED, result);
		detailedReport = createDetailedReport();
		checkBasicSignatureErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, false);
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, false);
		
		result = signatureConstraintAlgorithmExpired(ALGORITHM_RSA, "2019-01-01", 2048);
		assertEquals(Indication.TOTAL_PASSED, result);
		detailedReport = createDetailedReport();
		checkBasicSignatureErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_AKSNR, true); // PSV is not executed
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, false);
		
		result = signatureConstraintAlgorithmExpired(ALGORITHM_RSA, "2018-01-01", 2048);
		assertEquals(Indication.INDETERMINATE, result);
		detailedReport = createDetailedReport();
		checkBasicSignatureErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_AKSNR, true);
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, false);
		
		result = signatureConstraintAlgorithmExpired(ALGORITHM_RSA, "2019-01-01", 2048);
		assertEquals(Indication.TOTAL_PASSED, result);
		detailedReport = createDetailedReport();
		checkBasicSignatureErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_AKSNR, true); // PSV is not executed
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, false);
	}
	
	@Test
	public void invalidIntermediateGreaterValue() throws Exception {
		initializeExecutor("src/test/resources/diag_data_intermediate_algo_valid.xml");
		validationPolicyFile = new File("src/test/resources/policy/all-constraint-specified-policy.xml");
		
		Indication result = null;
		DetailedReport detailedReport = null;
		
		result = signatureConstraintAlgorithmExpired(ALGORITHM_RSA, "2018-01-01", 2048);
		assertEquals(Indication.INDETERMINATE, result);
		detailedReport = createDetailedReport();
		checkBasicSignatureErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_AKSNR, true);
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, false);

		result = signatureConstraintAlgorithmExpired(ALGORITHM_RSA, "2019-01-01", 2048);
		assertEquals(Indication.TOTAL_PASSED, result);
	}
	
	@Test
	public void invalidIntermediateLowerValue() throws Exception {
		initializeExecutor("src/test/resources/diag_data_intermediate_algo_invalid.xml");
		validationPolicyFile = new File("src/test/resources/policy/all-constraint-specified-policy.xml");
		
		Indication result = null;
		DetailedReport detailedReport = null;
		
		result = signatureConstraintAlgorithmExpired("RSA", "2018-01-01", 1536);
		assertEquals(Indication.INDETERMINATE, result);
		detailedReport = createDetailedReport();
		checkBasicSignatureErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_AKSNR, true);
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, false);
		
		result = signatureConstraintAlgorithmExpired(ALGORITHM_RSA, "2019-01-01", 2048);
		assertEquals(Indication.TOTAL_PASSED, result);
	}
	
	@Test
	public void algorithmHighestThanTheGreatestOne() throws Exception {
		initializeExecutor("src/test/resources/diag_data_inexisting_algo_date.xml");
		validationPolicyFile = new File("src/test/resources/policy/all-constraint-specified-policy.xml");
		
		Indication result = null;
		DetailedReport detailedReport = null;
		
		result = signatureConstraintAlgorithmExpired(ALGORITHM_RSA, "2018-01-01", 4096);
		assertEquals(Indication.INDETERMINATE, result);
		detailedReport = createDetailedReport();
		checkBasicSignatureErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_AKSNR, true);
		checkTimestampErrorPresence(detailedReport, MessageTag.ASCCM_AR_ANS_ANR, false);
		
		result = signatureConstraintAlgorithmExpired(ALGORITHM_RSA, "2019-01-01", 4096);
		assertEquals(Indication.TOTAL_PASSED, result);
	}
	
	@Test
	public void signatureWithContentTimestampTest() throws Exception {
		XmlDiagnosticData diagnosticData = initializeExecutor("src/test/resources/diag_data_pastSigValidation.xml");
		validationPolicyFile = new File("src/test/resources/policy/all-constraint-specified-policy.xml");
		
		Indication result = null;
		DetailedReport detailedReport = null;
		
		result = signatureConstraintAlgorithmExpired(ALGORITHM_SHA256, "2018-01-01", 0);
		assertEquals(Indication.INDETERMINATE, result);
		detailedReport = createDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));
		
		diagnosticData.getUsedTimestamps().get(0).setType(TimestampType.CONTENT_TIMESTAMP);

		result = signatureConstraintAlgorithmExpired(ALGORITHM_SHA256, "2020-01-01", 0);
		assertEquals(Indication.TOTAL_PASSED, result);
		result = signatureConstraintAlgorithmExpired(ALGORITHM_SHA256, "2018-01-01", 0);
		assertEquals(Indication.INDETERMINATE, result);
		detailedReport = createDetailedReport();
		assertEquals(Indication.INDETERMINATE, detailedReport.getBasicValidationIndication(detailedReport.getFirstSignatureId()));
		assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE, detailedReport.getBasicValidationSubIndication(detailedReport.getFirstSignatureId()));
	}
	
	private Indication defaultConstraintValidationDateIsBeforeExpirationDateTest(String algorithm, Integer keySize) throws Exception {
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CryptographicConstraint defaultCryptographicConstraint = constraintsParameters.getCryptographic();
		setAlgoExpDate(defaultCryptographicConstraint, algorithm, keySize, "2020-02-24");
		constraintsParameters.setCryptographic(defaultCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}
	
	private Indication defaultConstraintAlgorithmExpiredTest(String algorithm, Integer keySize) throws Exception {
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CryptographicConstraint defaultCryptographicConstraint = constraintsParameters.getCryptographic();
		setAlgoExpDate(defaultCryptographicConstraint, algorithm, keySize, "2015-02-24");
		constraintsParameters.setCryptographic(defaultCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}
	
	private Indication defaultConstraintAlgorithmExpirationDateIsNotDefined(String algorithm, Integer keySize) throws Exception {
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CryptographicConstraint defaultCryptographicConstraint = constraintsParameters.getCryptographic();
		AlgoExpirationDate algoExpirationDate = defaultCryptographicConstraint.getAlgoExpirationDate();
		List<Algo> algorithms = algoExpirationDate.getAlgo();
		removeAlgo(algorithms, algorithm, keySize);
		constraintsParameters.setCryptographic(defaultCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}
	
	private Indication defaultConstraintAcceptableDigestAlgorithmIsNotDefined(String algorithm, Integer keySize) throws Exception {
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CryptographicConstraint defaultCryptographicConstraint = constraintsParameters.getCryptographic();
		ListAlgo listAlgo = defaultCryptographicConstraint.getAcceptableDigestAlgo();
		List<Algo> algorithms = listAlgo.getAlgo();
		removeAlgo(algorithms, algorithm, keySize);
		constraintsParameters.setCryptographic(defaultCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}
	
	private Indication defaultConstraintAcceptableEncryptionAlgorithmIsNotDefined(String algorithm, Integer keySize) throws Exception {
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CryptographicConstraint defaultCryptographicConstraint = constraintsParameters.getCryptographic();
		ListAlgo listAlgo = defaultCryptographicConstraint.getAcceptableEncryptionAlgo();
		List<Algo> algorithms = listAlgo.getAlgo();
		removeAlgo(algorithms, algorithm, keySize);
		constraintsParameters.setCryptographic(defaultCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}
	
	private Indication defaultConstraintLargeMiniPublicKeySize(String algorithm) throws Exception {
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CryptographicConstraint defaultCryptographicConstraint = constraintsParameters.getCryptographic();
		ListAlgo listAlgo = defaultCryptographicConstraint.getMiniPublicKeySize();
		List<Algo> algorithms = listAlgo.getAlgo();
		setAlgorithmSize(algorithms, algorithm, 4096);
		constraintsParameters.setCryptographic(defaultCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}
	
	private Indication defaultConstraintSetLevelForPreviousValidationPolicy(Level level) throws Exception {
		ConstraintsParameters constraintsParameters = this.constraintsParameters;
		
		CryptographicConstraint defaultCryptographicConstraint = constraintsParameters.getCryptographic();
		defaultCryptographicConstraint.setLevel(level);
		constraintsParameters.setCryptographic(defaultCryptographicConstraint);
		setSignatureCryptographicConstraint(constraintsParameters, new CryptographicConstraint());
		
		CryptographicConstraint signCertCryptographicConstraint = getSigningCertificateConstraints(constraintsParameters).getCryptographic();
		signCertCryptographicConstraint.setLevel(level);
		setSigningCertificateConstraints(constraintsParameters, signCertCryptographicConstraint);
		
		CryptographicConstraint caCertCryptographicConstraint = getCACertificateConstraints(constraintsParameters).getCryptographic();
		caCertCryptographicConstraint.setLevel(level);
		setSigningCertificateConstraints(constraintsParameters, caCertCryptographicConstraint);
		
		CryptographicConstraint revocationCryptographicConstraint = constraintsParameters.getRevocation().getBasicSignatureConstraints().getCryptographic();
		revocationCryptographicConstraint.setLevel(level);
		
		CryptographicConstraint timestampCryptographicConstraint = constraintsParameters.getTimestamp().getBasicSignatureConstraints().getCryptographic();
		timestampCryptographicConstraint.setLevel(level);
		
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}
	
	private Indication signatureConstraintAlgorithmExpired(String algorithm, String date, Integer keySize) throws Exception {
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CryptographicConstraint sigCryptographicConstraint = getSignatureCryptographicConstraint(constraintsParameters);
		setAlgoExpDate(sigCryptographicConstraint, algorithm, keySize, date);
		setSignatureCryptographicConstraint(constraintsParameters, sigCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}
	
	private Indication signatureConstraintAlgorithmExpirationDateIsNotDefined(String algorithm, Integer keySize) throws Exception {
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CryptographicConstraint sigCryptographicConstraint = getSignatureCryptographicConstraint(constraintsParameters);
		AlgoExpirationDate algoExpirationDate = sigCryptographicConstraint.getAlgoExpirationDate();
		List<Algo> algorithms = algoExpirationDate.getAlgo();
		removeAlgo(algorithms, algorithm,keySize);
		setSignatureCryptographicConstraint(constraintsParameters, sigCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}
	
	private Indication signatureConstraintAcceptableDigestAlgorithmIsNotDefined(String algorithm, Integer keySize) throws Exception {
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CryptographicConstraint sigCryptographicConstraint = getSignatureCryptographicConstraint(constraintsParameters);
		ListAlgo listAlgo = sigCryptographicConstraint.getAcceptableDigestAlgo();
		List<Algo> algorithms = listAlgo.getAlgo();
		removeAlgo(algorithms, algorithm, keySize);
		setSignatureCryptographicConstraint(constraintsParameters, sigCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}
	
	private Indication signatureConstraintAcceptableEncriptionAlgorithmIsNotDefined(String algorithm, Integer keySize) throws Exception {
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CryptographicConstraint sigCryptographicConstraint = getSignatureCryptographicConstraint(constraintsParameters);
		ListAlgo listAlgo = sigCryptographicConstraint.getAcceptableEncryptionAlgo();
		List<Algo> algorithms = listAlgo.getAlgo();
		removeAlgo(algorithms, algorithm, keySize);
		setSignatureCryptographicConstraint(constraintsParameters, sigCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}
	
	private Indication signatureConstraintLargeMiniPublicKeySize(String algorithm) throws Exception {
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CryptographicConstraint sigCryptographicConstraint = getSignatureCryptographicConstraint(constraintsParameters);
		ListAlgo listAlgo = sigCryptographicConstraint.getMiniPublicKeySize();
		List<Algo> algorithms = listAlgo.getAlgo();
		setAlgorithmSize(algorithms, algorithm, 4096);
		setSignatureCryptographicConstraint(constraintsParameters, sigCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}

	private Indication revocationConstraintAcceptableEncryptionAlgorithmIsNotDefined(String algorithm, Integer keySize) throws Exception {
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CryptographicConstraint revocationCryptographicConstraint = getRevocationCryptographicConstraint(constraintsParameters);
		ListAlgo listAlgo = revocationCryptographicConstraint.getAcceptableEncryptionAlgo();
		List<Algo> algorithms = listAlgo.getAlgo();
		removeAlgo(algorithms, algorithm, keySize);
		revocationCryptographicConstraint.setAcceptableEncryptionAlgo(listAlgo);
		setRevocationCryptographicConstraint(constraintsParameters, revocationCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}

	private Indication revocationConstraintAcceptableDigestAlgorithmIsNotDefined(String algorithm, Integer keySize) throws Exception {
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CryptographicConstraint revocationCryptographicConstraint = getRevocationCryptographicConstraint(constraintsParameters);
		ListAlgo listAlgo = revocationCryptographicConstraint.getAcceptableDigestAlgo();
		List<Algo> algorithms = listAlgo.getAlgo();
		removeAlgo(algorithms, algorithm, keySize);
		revocationCryptographicConstraint.setAcceptableDigestAlgo(listAlgo);
		setRevocationCryptographicConstraint(constraintsParameters, revocationCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}

	private Indication timestampConstraintAcceptableDigestAlgorithmIsNotDefined(String algorithm, Integer keySize) throws Exception {
		ConstraintsParameters constraintsParameters = loadConstraintsParameters();
		CryptographicConstraint timestampCryptographicConstraint = getTimestampCryptographicConstraint(constraintsParameters);
		ListAlgo listAlgo = timestampCryptographicConstraint.getAcceptableDigestAlgo();
		List<Algo> algorithms = listAlgo.getAlgo();
		removeAlgo(algorithms, algorithm, keySize);
		timestampCryptographicConstraint.setAcceptableDigestAlgo(listAlgo);
		setTimestampCryptographicConstraints(constraintsParameters, timestampCryptographicConstraint);
		setValidationPolicy(constraintsParameters);
		SimpleReport simpleReport = createSimpleReport();
		return simpleReport.getIndication(simpleReport.getFirstSignatureId());
	}
	
	private void checkErrorMessageAbsence(MessageTag messageKey) {
		Reports reports = createReports();
		SimpleReport simpleReport = reports.getSimpleReport();
		checkErrorMessageAbsence(simpleReport, messageKey);
	}
	
	private void checkErrorMessageAbsence(SimpleReport simpleReport, MessageTag messageKey) {
		assertTrue(!simpleReport.getWarnings(simpleReport.getFirstSignatureId()).contains(i18nProvider.getMessage(messageKey)));
		assertTrue(!simpleReport.getErrors(simpleReport.getFirstSignatureId()).contains(i18nProvider.getMessage(messageKey)));
	}
	
	private void checkErrorMessagePresence(String message) {
		Reports reports = createReports();
		SimpleReport simpleReport = reports.getSimpleReport();
		checkErrorMessagePresence(simpleReport, message);
	}

	private void checkErrorMessagePresence(SimpleReport simpleReport, String message) {
		assertTrue(simpleReport.getWarnings(simpleReport.getFirstSignatureId()).contains(message));
	}
	
	private void checkBasicSignatureErrorPresence(DetailedReport detailedReport, MessageTag messageKey, boolean present) {
		List<XmlName> errors = detailedReport.getBasicBuildingBlockById(detailedReport.getFirstSignatureId()).getConclusion().getErrors();
		assertTrue(!present ^ xmlListContainsMessage(errors, messageKey));
	}
	
	private void checkRevocationErrorPresence(DetailedReport detailedReport, MessageTag messageKey, boolean present) {
		List<XmlName> listErrors = detailedReport.getBasicBuildingBlockById(detailedReport.getRevocationIds().get(0)).getSAV().getConclusion().getErrors();
		assertTrue(!present ^ xmlListContainsMessage(listErrors, messageKey));
	}
	
	private void checkTimestampErrorPresence(DetailedReport detailedReport, MessageTag messageKey, boolean present) {
		List<XmlName> listErrors = detailedReport.getBasicBuildingBlockById(detailedReport.getTimestampIds().get(0)).getSAV().getConclusion().getErrors();
		assertTrue(!present ^ xmlListContainsMessage(listErrors, messageKey));
	}
	
	private boolean xmlListContainsMessage(List<XmlName> list, MessageTag messageKey) {
		for (XmlName name : list) {
			if (messageKey.name().equals(name.getNameId())) {
				return true;
			}
		}
		return false;
	}

}

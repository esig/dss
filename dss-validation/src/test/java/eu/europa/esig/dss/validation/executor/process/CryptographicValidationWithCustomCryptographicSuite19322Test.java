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
package eu.europa.esig.dss.validation.executor.process;

import eu.europa.esig.dss.diagnostic.DiagnosticDataFacade;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDiagnosticData;
import eu.europa.esig.dss.enumerations.CryptographicSuiteAlgorithmUsage;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuite19322;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteAlgorithm;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteEvaluation;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteMetadata;
import eu.europa.esig.dss.model.policy.crypto.CryptographicSuiteParameter;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.executor.signature.DefaultSignatureProcessExecutor;
import eu.europa.esig.dss.validation.policy.CryptographicSuiteUtils;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class CryptographicValidationWithCustomCryptographicSuite19322Test extends AbstractProcessExecutorTest {

    private static final String DATE_FORMAT = "yyyy-MM-dd";

    @Test
    void validTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        List<CryptographicSuiteAlgorithm> algorithmList = new ArrayList<>();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256,
                Collections.singletonList(new EvaluationDTO(null, null))));
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512,
                Collections.singletonList(new EvaluationDTO(null, null))));
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA256,
                Collections.singletonList(new EvaluationDTO(null, null,
                        Collections.singletonList(new ParameterDTO(1024, 3000, CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER))))));
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA512,
                Collections.singletonList(new EvaluationDTO(null, null,
                        Collections.singletonList(new ParameterDTO(1024, CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER))))));

        CryptographicSuite19322 cryptographicSuite = new CryptographicSuite19322(new CryptographicSuiteMetadata(), algorithmList);

        ValidationPolicy validationPolicy = ValidationPolicyLoader.fromValidationPolicy(loadDefaultPolicy())
                .withCryptographicSuite(cryptographicSuite).create();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
    }

    @Test
    void digestAlgoExpiredTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        List<CryptographicSuiteAlgorithm> algorithmList = new ArrayList<>();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256,
                Collections.singletonList(new EvaluationDTO(null, "2020-01-01"))));
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512,
                Collections.singletonList(new EvaluationDTO(null, null))));
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA256,
                Collections.singletonList(new EvaluationDTO(null, null,
                        Collections.singletonList(new ParameterDTO(1024, CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER))))));
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA512,
                Collections.singletonList(new EvaluationDTO(null, null,
                        Collections.singletonList(new ParameterDTO(1024, CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER))))));

        CryptographicSuite19322 cryptographicSuite = new CryptographicSuite19322(new CryptographicSuiteMetadata(), algorithmList);

        ValidationPolicy validationPolicy = ValidationPolicyLoader.fromValidationPolicy(loadDefaultPolicy())
                .withCryptographicSuite(cryptographicSuite).create();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR, DigestAlgorithm.SHA256.getName(), MessageTag.ACCM_POS_REF)));

        validateBestSigningTimes(reports);
    }

    @Test
    void digestAlgoNotYetValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        List<CryptographicSuiteAlgorithm> algorithmList = new ArrayList<>();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256,
                Collections.singletonList(new EvaluationDTO("2022-01-01", null))));
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512,
                Collections.singletonList(new EvaluationDTO(null, null))));
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA256,
                Collections.singletonList(new EvaluationDTO(null, null,
                        Collections.singletonList(new ParameterDTO(1024, CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER))))));
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA512,
                Collections.singletonList(new EvaluationDTO(null, null,
                        Collections.singletonList(new ParameterDTO(1024, CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER))))));

        CryptographicSuite19322 cryptographicSuite = new CryptographicSuite19322(new CryptographicSuiteMetadata(), algorithmList);

        ValidationPolicy validationPolicy = ValidationPolicyLoader.fromValidationPolicy(loadDefaultPolicy())
                .withCryptographicSuite(cryptographicSuite).create();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_ANR_2, DigestAlgorithm.SHA256.getName(), MessageTag.ACCM_POS_REF)));

        validateBestSigningTimes(reports);
    }

    @Test
    void sigAlgoExpiredTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        List<CryptographicSuiteAlgorithm> algorithmList = new ArrayList<>();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256,
                Collections.singletonList(new EvaluationDTO(null, null))));
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512,
                Collections.singletonList(new EvaluationDTO(null, null))));
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA256,
                Collections.singletonList(new EvaluationDTO(null, "2020-01-01",
                        Collections.singletonList(new ParameterDTO(1024, CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER))))));
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA512,
                Collections.singletonList(new EvaluationDTO(null, null,
                        Collections.singletonList(new ParameterDTO(1024, CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER))))));

        CryptographicSuite19322 cryptographicSuite = new CryptographicSuite19322(new CryptographicSuiteMetadata(), algorithmList);

        ValidationPolicy validationPolicy = ValidationPolicyLoader.fromValidationPolicy(loadDefaultPolicy())
                .withCryptographicSuite(cryptographicSuite).create();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_AKSNR, SignatureAlgorithm.RSA_SHA256.getName(), "2048", MessageTag.ACCM_POS_SIG_SIG)));

        validateBestSigningTimes(reports);
    }

    @Test
    void sigAlgoNotYetValidTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        List<CryptographicSuiteAlgorithm> algorithmList = new ArrayList<>();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256,
                Collections.singletonList(new EvaluationDTO(null, null))));
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512,
                Collections.singletonList(new EvaluationDTO(null, null))));
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA256,
                Collections.singletonList(new EvaluationDTO("2022-01-01", null,
                        Collections.singletonList(new ParameterDTO(1024, CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER))))));
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA512,
                Collections.singletonList(new EvaluationDTO(null, null,
                        Collections.singletonList(new ParameterDTO(1024, CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER))))));

        CryptographicSuite19322 cryptographicSuite = new CryptographicSuite19322(new CryptographicSuiteMetadata(), algorithmList);

        ValidationPolicy validationPolicy = ValidationPolicyLoader.fromValidationPolicy(loadDefaultPolicy())
                .withCryptographicSuite(cryptographicSuite).create();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_AKSNR_2, SignatureAlgorithm.RSA_SHA256.getName(), "2048", MessageTag.ACCM_POS_SIG_SIG)));

        validateBestSigningTimes(reports);
    }

    @Test
    void sigAlgoKeyTooSmallTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        List<CryptographicSuiteAlgorithm> algorithmList = new ArrayList<>();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256,
                Collections.singletonList(new EvaluationDTO(null, null))));
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512,
                Collections.singletonList(new EvaluationDTO(null, null))));
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA256,
                Collections.singletonList(new EvaluationDTO(null, null,
                        Collections.singletonList(new ParameterDTO(3000, CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER))))));
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA512,
                Collections.singletonList(new EvaluationDTO(null, null,
                        Collections.singletonList(new ParameterDTO(1024, CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER))))));

        CryptographicSuite19322 cryptographicSuite = new CryptographicSuite19322(new CryptographicSuiteMetadata(), algorithmList);

        ValidationPolicy validationPolicy = ValidationPolicyLoader.fromValidationPolicy(loadDefaultPolicy())
                .withCryptographicSuite(cryptographicSuite).create();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_APKSA_ANS, SignatureAlgorithm.RSA_SHA256.getName(), "2048", MessageTag.ACCM_POS_SIG_SIG)));

        validateBestSigningTimes(reports);
    }

    @Test
    void sigAlgoKeyTooBigTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        List<CryptographicSuiteAlgorithm> algorithmList = new ArrayList<>();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256,
                Collections.singletonList(new EvaluationDTO(null, null))));
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA512,
                Collections.singletonList(new EvaluationDTO(null, null))));
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA256,
                Collections.singletonList(new EvaluationDTO(null, null,
                        Collections.singletonList(new ParameterDTO(1024, 1900, CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER))))));
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA512,
                Collections.singletonList(new EvaluationDTO(null, null,
                        Collections.singletonList(new ParameterDTO(1024, CryptographicSuiteUtils.MODULES_LENGTH_PARAMETER))))));

        CryptographicSuite19322 cryptographicSuite = new CryptographicSuite19322(new CryptographicSuiteMetadata(), algorithmList);

        ValidationPolicy validationPolicy = ValidationPolicyLoader.fromValidationPolicy(loadDefaultPolicy())
                .withCryptographicSuite(cryptographicSuite).create();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_APKSA_ANS_2, SignatureAlgorithm.RSA_SHA256.getName(), "2048", MessageTag.ACCM_POS_SIG_SIG)));

        validateBestSigningTimes(reports);
    }

    // See DSS-3804
    @Test
    void sigCertRestrictionXmlTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = ValidationPolicyLoader.fromValidationPolicy(loadDefaultPolicy())
                .withCryptographicSuite(new File("src/test/resources/diag-data/crypto-suite/allow-sha256withRSA-1900_sig-5000_cert.xml")).create();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
    }

    @Test
    void sigCertAllowanceXmlTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = ValidationPolicyLoader.fromValidationPolicy(loadDefaultPolicy())
                .withCryptographicSuite(new File("src/test/resources/diag-data/crypto-suite/allow-sha256withRSA-5000_sig-2000_cert.xml")).create();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_AKSNR, SignatureAlgorithm.RSA_SHA256.getName(), "2048", MessageTag.ACCM_POS_SIG_SIG)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_AKSNR, SignatureAlgorithm.RSA_SHA256.getName(), "2048", MessageTag.ACCM_POS_REVOC_SIG)));

        validateBestSigningTimes(reports);
    }

    @Test
    void sigCertRestrictionJsonTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = ValidationPolicyLoader.fromValidationPolicy(loadDefaultPolicy())
                .withCryptographicSuite(new File("src/test/resources/diag-data/crypto-suite/allow-sha256withRSA-1900_sig-5000_cert.json")).create();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));

        validateBestSigningTimes(reports);
    }

    @Test
    void sigCertAllowanceJsonTest() throws Exception {
        XmlDiagnosticData diagnosticData = DiagnosticDataFacade.newFacade().unmarshall(new File("src/test/resources/diag-data/valid-diag-data.xml"));
        assertNotNull(diagnosticData);

        ValidationPolicy validationPolicy = ValidationPolicyLoader.fromValidationPolicy(loadDefaultPolicy())
                .withCryptographicSuite(new File("src/test/resources/diag-data/crypto-suite/allow-sha256withRSA-5000_sig-2000_cert.json")).create();

        DefaultSignatureProcessExecutor executor = new DefaultSignatureProcessExecutor();
        executor.setDiagnosticData(diagnosticData);
        executor.setValidationPolicy(validationPolicy);
        executor.setCurrentTime(diagnosticData.getValidationDate());

        Reports reports = executor.execute();

        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.CRYPTO_CONSTRAINTS_FAILURE_NO_POE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_AKSNR, SignatureAlgorithm.RSA_SHA256.getName(), "2048", MessageTag.ACCM_POS_SIG_SIG)));
        assertTrue(checkMessageValuePresence(simpleReport.getAdESValidationErrors(simpleReport.getFirstSignatureId()),
                i18nProvider.getMessage(MessageTag.ASCCM_AR_ANS_AKSNR, SignatureAlgorithm.RSA_SHA256.getName(), "2048", MessageTag.ACCM_POS_REVOC_SIG)));

        validateBestSigningTimes(reports);
    }

    private CryptographicSuiteAlgorithm createDigestAlgorithmDefinition(DigestAlgorithm digestAlgorithm, List<EvaluationDTO> evaluationList) {
        CryptographicSuiteAlgorithm algorithm = new CryptographicSuiteAlgorithm();

        algorithm.setAlgorithmIdentifierName(digestAlgorithm.getName());
        if (digestAlgorithm.getOid() != null) {
            algorithm.setAlgorithmIdentifierOIDs(Collections.singletonList(digestAlgorithm.getOid()));
        }
        if (digestAlgorithm.getUri() != null) {
            algorithm.setAlgorithmIdentifierURIs(Collections.singletonList(digestAlgorithm.getUri()));
        }

        algorithm.setEvaluationList(new ArrayList<>(createEvaluations(evaluationList)));

        return algorithm;
    }

    private CryptographicSuiteAlgorithm createSignatureAlgorithmDefinition(SignatureAlgorithm signatureAlgorithm, List<EvaluationDTO> evaluationList) {
        CryptographicSuiteAlgorithm algorithm = new CryptographicSuiteAlgorithm();

        algorithm.setAlgorithmIdentifierName(signatureAlgorithm.getName());
        if (signatureAlgorithm.getOid() != null) {
            algorithm.setAlgorithmIdentifierOIDs(Collections.singletonList(signatureAlgorithm.getOid()));
        }
        if (signatureAlgorithm.getUri() != null) {
            algorithm.setAlgorithmIdentifierURIs(Collections.singletonList(signatureAlgorithm.getUri()));
        }

        algorithm.setEvaluationList(new ArrayList<>(createEvaluations(evaluationList)));

        return algorithm;
    }

    private Set<CryptographicSuiteEvaluation> createEvaluations(List<EvaluationDTO> evaluationList) {
        Set<CryptographicSuiteEvaluation> result = new HashSet<>();
        if (evaluationList != null && !evaluationList.isEmpty()) {
            for (EvaluationDTO evaluationDTO : evaluationList) {
                CryptographicSuiteEvaluation evaluation = new CryptographicSuiteEvaluation();
                evaluation.setValidityStart(toDate(evaluationDTO.validityStart));
                evaluation.setValidityEnd(toDate(evaluationDTO.validityEnd));

                if (evaluationDTO.parameterList != null && !evaluationDTO.parameterList.isEmpty()) {
                    List<CryptographicSuiteParameter> parameters = new ArrayList<>();
                    for (ParameterDTO parameterDTO : evaluationDTO.parameterList) {
                        CryptographicSuiteParameter parameter = new CryptographicSuiteParameter();
                        parameter.setMin(parameterDTO.minKeyLength);
                        parameter.setMax(parameterDTO.maxKeyLength);
                        parameter.setName(parameterDTO.parameterName);
                        parameters.add(parameter);
                    }
                    evaluation.setParameterList(parameters);
                }
                if (evaluationDTO.usages != null && !evaluationDTO.usages.isEmpty()) {
                    evaluation.setAlgorithmUsage(evaluationDTO.usages);
                }

                result.add(evaluation);
            }

        } else {
            CryptographicSuiteEvaluation evaluationType = new CryptographicSuiteEvaluation();
            result.add(evaluationType);
        }
        return result;
    }

    private Date toDate(final String str) {
        if (str == null) {
            return null;
        }
        try {
            SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
            sdf.setTimeZone(TimeZone.getTimeZone("GMT+0"));
            return sdf.parse(str);
        } catch (Exception e) {
            fail(e);
            return null;
        }
    }

    private static class EvaluationDTO {

        private final String validityStart;
        private final String validityEnd;
        private final List<ParameterDTO> parameterList;
        private final List<CryptographicSuiteAlgorithmUsage> usages;

        public EvaluationDTO(final String validityStart, final String validityEnd) {
            this(validityStart, validityEnd, null, null);
        }

        public EvaluationDTO(final String validityStart, final String validityEnd, final List<ParameterDTO> parameterList) {
            this(validityStart, validityEnd, parameterList, null);
        }

        public EvaluationDTO(final String validityStart, final String validityEnd, final List<ParameterDTO> parameterList,
                             final List<CryptographicSuiteAlgorithmUsage> usages) {
            this.validityStart = validityStart;
            this.validityEnd = validityEnd;
            this.parameterList = parameterList;
            this.usages = usages;
        }

    }

    private static class ParameterDTO {

        private final Integer minKeyLength;
        private final Integer maxKeyLength;
        private final String parameterName;

        public ParameterDTO(final Integer minKeyLength, final String parameterName) {
            this(minKeyLength, null, parameterName);
        }

        public ParameterDTO(final Integer minKeyLength, final Integer maxKeyLength, final String parameterName) {
            this.minKeyLength = minKeyLength;
            this.maxKeyLength = maxKeyLength;
            this.parameterName = parameterName;
        }

    }

}

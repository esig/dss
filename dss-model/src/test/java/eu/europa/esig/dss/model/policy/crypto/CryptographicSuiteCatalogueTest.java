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
package eu.europa.esig.dss.model.policy.crypto;

import eu.europa.esig.dss.enumerations.CryptographicSuiteAlgorithmUsage;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

class CryptographicSuiteCatalogueTest {

    private static final String DATE_FORMAT = "yyyy-MM-dd";

    @Test
    void digestAlgorithmUsagesTest() {
        List<CryptographicSuiteAlgorithm> algorithmList = new ArrayList<>();

        // global usage
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01"))));

        CryptographicSuiteCatalogue cryptographicSuiteCatalogue = new MockCryptographicSuiteCatalogue(algorithmList);

        Set<DigestAlgorithm> emptySet = Collections.emptySet();
        Set<DigestAlgorithm> expectedSet = new HashSet<>(Collections.singletonList(DigestAlgorithm.SHA224));

        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.SIGN_DATA)))));

        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.SIGN_CERTIFICATES)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_CERTIFICATES)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_DATA)))));

        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.SIGN_OCSP)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_OCSP)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.SIGN_TIMESTAMPS)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_TIMESTAMPS)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Arrays.asList(CryptographicSuiteAlgorithmUsage.VALIDATE_OCSP, CryptographicSuiteAlgorithmUsage.VALIDATE_TIMESTAMPS)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());

        // add global
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256,
                Collections.singletonList(new EvaluationDTO(null))));

        Set<DigestAlgorithm> sha256Set = new HashSet<>(Collections.singletonList(DigestAlgorithm.SHA256));
        Set<DigestAlgorithm> fullSet = new HashSet<>(Arrays.asList(DigestAlgorithm.SHA224, DigestAlgorithm.SHA256));

        assertEquals(sha256Set, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(fullSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(fullSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(fullSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(fullSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableDigestAlgorithms().keySet());
    }

    @Test
    void signatureAlgorithmUsagesTest() {
        List<CryptographicSuiteAlgorithm> algorithmList = new ArrayList<>();

        // global usage
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01"))));

        CryptographicSuiteCatalogue cryptographicSuiteCatalogue = new MockCryptographicSuiteCatalogue(algorithmList);

        Set<SignatureAlgorithm> emptySet = Collections.emptySet();
        Set<SignatureAlgorithm> expectedSet = new HashSet<>(Collections.singletonList(SignatureAlgorithm.RSA_SHA224));

        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.SIGN_DATA)))));

        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.SIGN_CERTIFICATES)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_CERTIFICATES)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_DATA)))));

        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.SIGN_OCSP)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_OCSP)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.SIGN_TIMESTAMPS)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_TIMESTAMPS)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Arrays.asList(CryptographicSuiteAlgorithmUsage.VALIDATE_OCSP, CryptographicSuiteAlgorithmUsage.VALIDATE_TIMESTAMPS)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        // add global
        algorithmList.add(createSignatureAlgorithmDefinition(SignatureAlgorithm.RSA_SHA256,
                Collections.singletonList(new EvaluationDTO(null))));

        Set<SignatureAlgorithm> sha256Set = new HashSet<>(Collections.singletonList(SignatureAlgorithm.RSA_SHA256));
        Set<SignatureAlgorithm> fullSet = new HashSet<>(Arrays.asList(SignatureAlgorithm.RSA_SHA224, SignatureAlgorithm.RSA_SHA256));

        assertEquals(sha256Set, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(fullSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(fullSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(fullSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(fullSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
    }

    @Test
    void digestAndSignatureAlgorithmCombinationUsagesTest() {
        List<CryptographicSuiteAlgorithm> algorithmList = new ArrayList<>();

        // global usage
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01"))));
        algorithmList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA,
                Collections.singletonList(new EvaluationDTO("2029-01-01"))));

        CryptographicSuiteCatalogue cryptographicSuiteCatalogue = new MockCryptographicSuiteCatalogue(algorithmList);

        Set<SignatureAlgorithm> emptySet = Collections.emptySet();
        Set<SignatureAlgorithm> expectedSet = new HashSet<>(Collections.singletonList(SignatureAlgorithm.RSA_SHA224));

        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.SIGN_DATA)))));
        algorithmList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA,
                Collections.singletonList(new EvaluationDTO("2029-01-01"))));

        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.SIGN_CERTIFICATES)))));
        algorithmList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA,
                Collections.singletonList(new EvaluationDTO("2029-01-01"))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_CERTIFICATES)))));
        algorithmList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA,
                Collections.singletonList(new EvaluationDTO("2029-01-01"))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_DATA)))));
        algorithmList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA,
                Collections.singletonList(new EvaluationDTO("2029-01-01"))));

        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.SIGN_OCSP)))));
        algorithmList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA,
                Collections.singletonList(new EvaluationDTO("2029-01-01"))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_OCSP)))));
        algorithmList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA,
                Collections.singletonList(new EvaluationDTO("2029-01-01"))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.SIGN_TIMESTAMPS)))));
        algorithmList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA,
                Collections.singletonList(new EvaluationDTO("2029-01-01"))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_TIMESTAMPS)))));
        algorithmList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA,
                Collections.singletonList(new EvaluationDTO("2029-01-01"))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Arrays.asList(CryptographicSuiteAlgorithmUsage.VALIDATE_OCSP, CryptographicSuiteAlgorithmUsage.VALIDATE_TIMESTAMPS)))));
        algorithmList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA,
                Collections.singletonList(new EvaluationDTO("2029-01-01"))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        // add global
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA256,
                Collections.singletonList(new EvaluationDTO(null))));

        Set<SignatureAlgorithm> sha256Set = new HashSet<>(Collections.singletonList(SignatureAlgorithm.RSA_SHA256));
        Set<SignatureAlgorithm> fullSet = new HashSet<>(Arrays.asList(SignatureAlgorithm.RSA_SHA224, SignatureAlgorithm.RSA_SHA256));

        assertEquals(sha256Set, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(fullSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(fullSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(fullSet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(fullSet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(sha256Set, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        // same definitions
        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_OCSP)))));
        algorithmList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_OCSP)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        // same inclusive
        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_OCSP)))));
        algorithmList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_DATA)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(expectedSet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());

        // different
        algorithmList.clear();
        algorithmList.add(createDigestAlgorithmDefinition(DigestAlgorithm.SHA224,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_OCSP)))));
        algorithmList.add(createEncryptionAlgorithmDefinition(EncryptionAlgorithm.RSA,
                Collections.singletonList(new EvaluationDTO("2029-01-01", null, Collections.singletonList(CryptographicSuiteAlgorithmUsage.VALIDATE_TIMESTAMPS)))));

        assertEquals(emptySet, cryptographicSuiteCatalogue.getCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getCounterSignatureCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getRevocationCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getTimestampCertificatesCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getEvidenceRecordCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
        assertEquals(emptySet, cryptographicSuiteCatalogue.getAttestationCryptographicSuite().getAcceptableSignatureAlgorithms().keySet());
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

    private CryptographicSuiteAlgorithm createEncryptionAlgorithmDefinition(EncryptionAlgorithm encryptionAlgorithm, List<EvaluationDTO> evaluationList) {
        CryptographicSuiteAlgorithm algorithm = new CryptographicSuiteAlgorithm();

        algorithm.setAlgorithmIdentifierName(encryptionAlgorithm.getName());
        if (encryptionAlgorithm.getOid() != null) {
            algorithm.setAlgorithmIdentifierOIDs(Collections.singletonList(encryptionAlgorithm.getOid()));
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
                evaluation.setValidityEnd(toDate(evaluationDTO.validityEnd));

                if (evaluationDTO.parameterList != null && !evaluationDTO.parameterList.isEmpty()) {
                    List<CryptographicSuiteParameter> parameters = new ArrayList<>();
                    for (ParameterDTO parameterDTO : evaluationDTO.parameterList) {
                        CryptographicSuiteParameter parameter = new CryptographicSuiteParameter();
                        parameter.setMin(parameterDTO.minKeyLength);
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

        private final String validityEnd;
        private final List<ParameterDTO> parameterList;
        private final List<CryptographicSuiteAlgorithmUsage> usages;

        public EvaluationDTO(final String validityEnd) {
            this(validityEnd, null, null);
        }

        public EvaluationDTO(final String validityEnd, final List<ParameterDTO> parameterList) {
            this(validityEnd, parameterList, null);
        }

        public EvaluationDTO(final String validityEnd, final List<ParameterDTO> parameterList, final List<CryptographicSuiteAlgorithmUsage> usages) {
            this.validityEnd = validityEnd;
            this.parameterList = parameterList;
            this.usages = usages;
        }

    }

    private static class ParameterDTO {

        private final Integer minKeyLength;
        private final String parameterName;

        public ParameterDTO(final Integer minKeyLength, final String parameterName) {
            this.minKeyLength = minKeyLength;
            this.parameterName = parameterName;
        }

    }

    private static class MockCryptographicSuiteCatalogue extends CryptographicSuiteCatalogue {

        private final List<CryptographicSuiteAlgorithm> algorithmList;

        private MockCryptographicSuiteCatalogue(final List<CryptographicSuiteAlgorithm> algorithmList) {
            this.algorithmList = algorithmList;
        }

        @Override
        protected CryptographicSuiteMetadata buildMetadata() {
            return new CryptographicSuiteMetadata();
        }

        @Override
        protected List<CryptographicSuiteAlgorithm> buildAlgorithmList() {
            return algorithmList;
        }

    }
    
}

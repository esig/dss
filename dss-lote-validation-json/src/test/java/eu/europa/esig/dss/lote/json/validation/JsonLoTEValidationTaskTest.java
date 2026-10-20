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
package eu.europa.esig.dss.lote.json.validation;

import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.lote.validation.LoTEValidationResult;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.policy.ValidationPolicy;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.x509.CertificateSource;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.validation.job.validation.ValidationResult;
import eu.europa.esig.dss.validation.policy.ValidationPolicyLoader;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JsonLoTEValidationTaskTest {

    private static final DSSDocument PID_PROVIDERS;
    private static final CertificateToken PID_PROVIDERS_SIGNER;

    private static ValidationPolicy validationPolicy;

    static {
        PID_PROVIDERS = new FileDocument("src/test/resources/pid-providers.json");
        PID_PROVIDERS_SIGNER = DSSUtils.loadCertificate(new File("src/test/resources/pid-providers-cert.cer"));

        validationPolicy = ValidationPolicyLoader.fromValidationPolicy(
                JsonLoTEValidationTaskTest.class.getResourceAsStream("/policy/te-json-constraint.xml")).create();
    }

    @Test
    void testValid() {
        List<CertificateToken> potentialSigners = Collections.singletonList(PID_PROVIDERS_SIGNER);
        JsonLoTEValidationTask task = new JsonLoTEValidationTask(PID_PROVIDERS, getCertificateSource(potentialSigners), validationPolicy);
        LoTEValidationResult result = task.get();
        assertNotNull(result);
        assertEquals(Indication.TOTAL_PASSED, result.getIndication());
        assertNotNull(result.getSigningTime());
        assertNotNull(result.getSigningCertificate());
        assertEquals(PID_PROVIDERS_SIGNER, result.getSigningCertificate());
    }

    @Test
    void testCACert() {
        // LoTE shall be signed with a trusted certificate directly
        CertificateToken potentialSigner = DSSUtils.loadCertificateFromBase64EncodedString("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");
        List<CertificateToken> potentialSigners = Collections.singletonList(potentialSigner);
        JsonLoTEValidationTask task = new JsonLoTEValidationTask(PID_PROVIDERS, getCertificateSource(potentialSigners), validationPolicy);
        LoTEValidationResult result = task.get();
        assertNotNull(result);
        assertEquals(Indication.INDETERMINATE, result.getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication());
        assertNotNull(result.getSigningTime());
        assertNotNull(result.getSigningCertificate());
        assertNotEquals(potentialSigner, result.getSigningCertificate());
    }

    @Test
    void testWrongCert() {
        CertificateToken potentialSigner = DSSUtils.loadCertificateFromBase64EncodedString("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");
        List<CertificateToken> potentialSigners = Collections.singletonList(potentialSigner);
        JsonLoTEValidationTask task = new JsonLoTEValidationTask(PID_PROVIDERS, getCertificateSource(potentialSigners), validationPolicy);
        LoTEValidationResult result = task.get();
        assertNotNull(result);
        assertEquals(Indication.INDETERMINATE, result.getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication());
        assertNotNull(result.getSigningTime());
        assertNotNull(result.getSigningCertificate());
        assertNotEquals(potentialSigner, result.getSigningCertificate());
    }

    @Test
    void testNoCert() {
        JsonLoTEValidationTask task = new JsonLoTEValidationTask(PID_PROVIDERS, getCertificateSource(Collections.emptyList()), validationPolicy);
        ValidationResult result = task.get();
        assertNotNull(result);
        assertEquals(Indication.INDETERMINATE, result.getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication());
        assertNotNull(result.getSigningTime());
        assertNotNull(result.getSigningCertificate());
    }

    @Test
    void testInvalidSignature() {
        DSSDocument loteDoc = new FileDocument("src/test/resources/pid-providers-broken-sig.json");
        CertificateToken potentialSigner = DSSUtils.loadCertificate(new File("src/test/resources/pid-providers-cert.cer"));
        List<CertificateToken> potentialSigners = Collections.singletonList(potentialSigner);
        JsonLoTEValidationTask task = new JsonLoTEValidationTask(loteDoc, getCertificateSource(potentialSigners), validationPolicy);
        LoTEValidationResult result = task.get();
        assertNotNull(result);
        assertEquals(Indication.TOTAL_FAILED, result.getIndication());
        assertEquals(SubIndication.HASH_FAILURE, result.getSubIndication());
        assertNotNull(result.getSigningTime());
        assertNotNull(result.getSigningCertificate());
        assertEquals(potentialSigner, result.getSigningCertificate());
    }

    @Test
    void testBrokenLoTE() {
        DSSDocument loteDoc = new FileDocument("src/test/resources/pid-providers-broken-json.json");
        CertificateToken potentialSigner = DSSUtils.loadCertificate(new File("src/test/resources/pid-providers-cert.cer"));
        List<CertificateToken> potentialSigners = Collections.singletonList(potentialSigner);
        JsonLoTEValidationTask task = new JsonLoTEValidationTask(loteDoc, getCertificateSource(potentialSigners), validationPolicy);
        ValidationResult result = task.get();
        assertNotNull(result);
        assertEquals(Indication.INDETERMINATE, result.getIndication());
        assertEquals(SubIndication.NO_CERTIFICATE_CHAIN_FOUND, result.getSubIndication());
        assertNotNull(result.getSigningTime());
        assertNotNull(result.getSigningCertificate());
    }

    @Test
    void testNullCertSource() {
        assertThrows(NullPointerException.class, () -> new JsonLoTEValidationTask(PID_PROVIDERS, null, validationPolicy));
    }

    @Test
    void testNullDoc() {
        CommonCertificateSource ccs = new CommonCertificateSource();
        assertThrows(NullPointerException.class, () -> new JsonLoTEValidationTask(null, ccs, validationPolicy));
    }

    private CertificateSource getCertificateSource(List<CertificateToken> potentialSigners) {
        CertificateSource cs = new CommonCertificateSource();
        for (CertificateToken certificateToken : potentialSigners) {
            cs.addCertificate(certificateToken);
        }
        return cs;
    }

}

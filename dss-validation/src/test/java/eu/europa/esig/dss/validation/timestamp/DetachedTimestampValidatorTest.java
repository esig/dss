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
package eu.europa.esig.dss.validation.timestamp;

import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CertificateRef;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampCertificateSource;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class DetachedTimestampValidatorTest {

    @Test
    public void testWithAttached() throws Exception {
        DSSDocument timestamp = new FileDocument("src/test/resources/d-trust.tsr");
        DSSDocument timestampedContent = new InMemoryDocument("Test123".getBytes());

        DetachedTimestampValidator timestampValidator = new DetachedTimestampValidator(timestamp);
        timestampValidator.setTimestampedData(timestampedContent);
        timestampValidator.setCertificateVerifier(getOfflineCertificateVerifier());

        Reports reports = timestampValidator.validateDocument();
        DiagnosticData diagnosticData = reports.getDiagnosticData();

        for (CertificateWrapper cert : diagnosticData.getUsedCertificates()) {
            assertEquals(EncryptionAlgorithm.RSASSA_PSS, cert.getSignatureAlgorithm().getEncryptionAlgorithm());
        }

        assertEquals(1, diagnosticData.getTimestampList().size());
        for (TimestampWrapper tst : diagnosticData.getTimestampList()) {
            assertEquals(EncryptionAlgorithm.RSASSA_PSS, tst.getSignatureAlgorithm().getEncryptionAlgorithm());
        }

        validate(reports);
    }

    @Test
    public void sdv1() throws Exception {
        DSSDocument timestamp = new FileDocument("src/test/resources/d-trust.tsr");
        DSSDocument timestampedContent = new InMemoryDocument("Test123".getBytes());

        DetachedTimestampValidator validator = new DetachedTimestampValidator(timestamp);
        validator.setTimestampedData(timestampedContent);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        validate(validator.validateDocument());
    }

    @Test
    public void sdv2() throws Exception {
        DSSDocument timestamp = new FileDocument("src/test/resources/d-trust.tsr");
        DSSDocument timestampedContent = new InMemoryDocument("Test123".getBytes());

        DetachedTimestampValidator validator = new DetachedTimestampValidator(timestamp);
        validator.setDetachedContents(Collections.singletonList(timestampedContent));
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        validate(validator.validateDocument());
    }

    @Test
    public void sdvNoFile() throws Exception {
        DSSDocument timestamp = new FileDocument("src/test/resources/d-trust.tsr");

        DetachedTimestampValidator validator = new DetachedTimestampValidator(timestamp);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        Reports reports = validator.validateDocument();
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        TimestampWrapper timestampWrapper = diagnosticData.getTimestampList().iterator().next();
        assertFalse(timestampWrapper.isMessageImprintDataFound());
        assertFalse(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertFalse(timestampWrapper.isSignatureValid());

        validator = new DetachedTimestampValidator(timestamp);
        validator.setDetachedContents(new ArrayList<>());
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        reports = validator.validateDocument();
        diagnosticData = reports.getDiagnosticData();
        timestampWrapper = diagnosticData.getTimestampList().iterator().next();
        assertFalse(timestampWrapper.isMessageImprintDataFound());
        assertFalse(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertFalse(timestampWrapper.isSignatureValid());

        validator = new DetachedTimestampValidator(timestamp);
        validator.setDetachedContents(Collections.singletonList(new InMemoryDocument("Wrong data".getBytes(StandardCharsets.UTF_8))));
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        reports = validator.validateDocument();
        diagnosticData = reports.getDiagnosticData();
        timestampWrapper = diagnosticData.getTimestampList().iterator().next();
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertFalse(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertFalse(timestampWrapper.isSignatureValid());

        assertEquals(0, timestampWrapper.getTimestampScopes().size());
        assertEquals(0, timestampWrapper.getTimestampedObjects().size());
    }

    @Test
    public void detachedNoFile() throws Exception {
        DSSDocument timestamp = new FileDocument("src/test/resources/d-trust.tsr");

        DetachedTimestampValidator validator = new DetachedTimestampValidator(timestamp);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());

        Reports reports = validator.validateDocument();
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        TimestampWrapper timestampWrapper = diagnosticData.getTimestampList().iterator().next();

        assertFalse(timestampWrapper.isMessageImprintDataFound());
        assertFalse(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertFalse(timestampWrapper.isSignatureValid());
    }

    @Test
    public void sdvTooMuchFiles() {
        DSSDocument timestamp = new FileDocument("src/test/resources/d-trust.tsr");
        DSSDocument timestampedContent = new InMemoryDocument("Test123".getBytes());

        DetachedTimestampValidator validator = new DetachedTimestampValidator(timestamp);
        validator.setDetachedContents(Arrays.asList(timestampedContent, timestampedContent));
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        Exception exception = assertThrows(IllegalArgumentException.class, validator::validateDocument);
        assertEquals("Only one detached document shall be provided for a timestamp validation!", exception.getMessage());
    }

    @Test
    public void testWithDigestDocument() throws Exception {

        FileDocument timestamp = new FileDocument("src/test/resources/d-trust.tsr");
        TimestampToken tst = new TimestampToken(DSSUtils.toByteArray(timestamp), TimestampType.CONTENT_TIMESTAMP);
        DigestAlgorithm algorithm = tst.getMessageImprint().getAlgorithm();
        assertNotNull(algorithm);

        DigestDocument digestDocument = new DigestDocument(algorithm, Utils.toBase64(DSSUtils.digest(algorithm, "Test123".getBytes())));
        DetachedTimestampValidator timestampValidator = new DetachedTimestampValidator(timestamp);

        assertThrows(NullPointerException.class, () -> timestampValidator.setTimestampedData(null));

        timestampValidator.setTimestampedData(digestDocument);
        timestampValidator.setCertificateVerifier(getOfflineCertificateVerifier());

        validate(timestampValidator.validateDocument());
    }

    @Test
    public void disig() throws Exception {
        DSSDocument tst = new FileDocument("src/test/resources/disig.tst");

        try (InputStream fis = tst.openStream()) {
            byte[] byteArray = Utils.toByteArray(fis);
            TimestampToken token = new TimestampToken(byteArray, TimestampType.ARCHIVE_TIMESTAMP);
            TimestampCertificateSource certificateSource = token.getCertificateSource();
            List<CertificateToken> certificates = certificateSource.getCertificates();
            assertEquals(2, certificates.size());
            assertNotEquals(certificates.get(0), certificates.get(1));
            assertTrue(certificates.get(0).isEquivalent(certificates.get(1)));

            List<CertificateRef> refs = certificateSource.getSigningCertificateRefs();
            assertEquals(2, refs.size());
            assertNotEquals(refs.get(0), refs.get(1));

            Set<CertificateToken> sigCertValues = certificateSource.getSigningCertificates();
            assertEquals(1, sigCertValues.size());

            for (CertificateRef certificateRef : refs) {
                for (CertificateToken sigCertValue : sigCertValues) {
                    assertArrayEquals(sigCertValue.getDigest(certificateRef.getCertDigest().getAlgorithm()), certificateRef.getCertDigest().getValue());
                }
            }
            for (CertificateToken certificateToken : sigCertValues) {
                assertTrue(token.isSignedBy(certificateToken));
            }

            // no Trust anchor
            DetachedTimestampValidator validator = new DetachedTimestampValidator(tst);
            CommonCertificateVerifier certificateVerifier = new CommonCertificateVerifier();
            validator.setCertificateVerifier(certificateVerifier);

            Reports reports = validator.validateDocument();
            DiagnosticData diagnosticData = reports.getDiagnosticData();
            assertEquals(1, Utils.collectionSize(diagnosticData.getTimestampList()));

            TimestampWrapper timestampWrapper = diagnosticData.getTimestampList().iterator().next();
            assertTrue(timestampWrapper.isSignatureIntact());

            String b1 = "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";
            String b2 = "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";

            // 1st TSU as Trust anchor
            validator = new DetachedTimestampValidator(tst);
            CommonTrustedCertificateSource trustedCertSource = new CommonTrustedCertificateSource();
            trustedCertSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(b1));
            certificateVerifier.setTrustedCertSources(trustedCertSource);
            validator.setCertificateVerifier(certificateVerifier);

            reports = validator.validateDocument();
            diagnosticData = reports.getDiagnosticData();
            assertEquals(1, Utils.collectionSize(diagnosticData.getTimestampList()));

            timestampWrapper = diagnosticData.getTimestampList().iterator().next();
            assertTrue(timestampWrapper.isSignatureIntact());

            // 2nd TSU as Trust anchor
            validator = new DetachedTimestampValidator(tst);
            trustedCertSource = new CommonTrustedCertificateSource();
            trustedCertSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(b2));
            certificateVerifier.setTrustedCertSources(trustedCertSource);

            validator.setCertificateVerifier(certificateVerifier);

            reports = validator.validateDocument();
            diagnosticData = reports.getDiagnosticData();
            assertEquals(1, Utils.collectionSize(diagnosticData.getTimestampList()));

            timestampWrapper = diagnosticData.getTimestampList().iterator().next();
            assertTrue(timestampWrapper.isSignatureIntact());
            assertTrue(timestampWrapper.isSignatureIntact());

            // both TSU as Trust anchor
            validator = new DetachedTimestampValidator(tst);
            trustedCertSource = new CommonTrustedCertificateSource();
            trustedCertSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(b1));
            trustedCertSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString(b2));
            certificateVerifier.setTrustedCertSources(trustedCertSource);

            validator.setCertificateVerifier(certificateVerifier);

            reports = validator.validateDocument();
            diagnosticData = reports.getDiagnosticData();
            assertEquals(1, Utils.collectionSize(diagnosticData.getTimestampList()));

            timestampWrapper = diagnosticData.getTimestampList().iterator().next();
            assertTrue(timestampWrapper.isSignatureIntact());
            assertTrue(timestampWrapper.isSignatureIntact());
        }
    }

    private void validate(Reports reports) throws Exception {
        assertNotNull(reports);

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertNotNull(diagnosticData);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(1, timestampList.size());
        TimestampWrapper timestampWrapper = timestampList.iterator().next();

        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());

        assertEquals(1, timestampWrapper.getTimestampScopes().size());
        assertEquals(1, timestampWrapper.getTimestampedObjects().size());
    }

    private CertificateVerifier getOfflineCertificateVerifier() {
        CertificateVerifier cv = new CommonCertificateVerifier();
        cv.setAIASource(null);
        return cv;
    }

}

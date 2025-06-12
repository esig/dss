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
package eu.europa.esig.dss.xades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.i18n.MessageTag;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelLTDetachedWithEmbeddedEvidenceRecordSignedDataNotCoveredOrphanRefTest extends AbstractXAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/X-E-ERS-DETACHED-LT-orphan-ref.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new FileDocument("src/test/resources/sample.xml"));
    }

    @Override
    protected CertificateVerifier getOfflineCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getOfflineCertificateVerifier();
        CommonTrustedCertificateSource trustedCertificateSource = new CommonTrustedCertificateSource();
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIERzCCA86gAwIBAgIUEFsEYuhn+NxO8EbEovbXNQS+YskwCgYIKoZIzj0EAwMwgbsxCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEwMC4GA1UECgwnS2luZ2RvbSBvZiBCZWxnaXVtIC0gRmVkZXJhbCBHb3Zlcm5tZW50MT8wPQYDVQQLDDZRVFNQOiBGUFMgUG9saWN5IGFuZCBTdXBwb3J0IC0gQk9TQSAoTlRSQkUtMDY3MTUxNjY0NykxDzANBgNVBAUTBjIwMjEwMTEVMBMGA1UEAwwMVGltZXN0YW1wIENBMB4XDTIxMDMxNjA5NDAyNFoXDTI3MDMxNjA5NDAyNFowgb0xCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEwMC4GA1UECgwnS2luZ2RvbSBvZiBCZWxnaXVtIC0gRmVkZXJhbCBHb3Zlcm5tZW50MT8wPQYDVQQLDDZRVFNQOiBGUFMgUG9saWN5IGFuZCBTdXBwb3J0IC0gQk9TQSAoTlRSQkUtMDY3MTUxNjY0NykxDzANBgNVBAUTBjIwMjEwMjEXMBUGA1UEAwwOVGltZXN0YW1wIFVuaXQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQgW045n8P+kf/32AZ+HfDC+it91DWvUg1VuyLBPXklBXS2aJ3SoWleLm9dbBIR+dN2VnGNpxJeWJwkrLV6ed6Co4IBqjCCAaYwDAYDVR0TAQH/BAIwADAfBgNVHSMEGDAWgBTgThvTdU21h04CtvqpWmPMPKqYmTB7BggrBgEFBQcBAQRvMG0wOgYIKwYBBQUHMAKGLmh0dHA6Ly9jcnQuZWlkcGtpLmJlbGdpdW0uYmUvdHMvdHNjYTIwMjEwMS5jcnQwLwYIKwYBBQUHMAGGI2h0dHA6Ly9vY3NwLmVpZHBraS5iZWxnaXVtLmJlL2VpZC8wMFYGA1UdIARPME0wQAYHYDgNBgOHaDA1MDMGCCsGAQUFBwIBFidodHRwczovL3JlcG9zaXRvcnkuZWlkcGtpLmJlbGdpdW0uYmUvdHMwCQYHBACL7EABATAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAYBggrBgEFBQcBAwQMMAowCAYGBACORgEBMD8GA1UdHwQ4MDYwNKAyoDCGLmh0dHA6Ly9jcmwuZWlkcGtpLmJlbGdpdW0uYmUvdHMvdHNjYTIwMjEwMS5jcmwwHQYDVR0OBBYEFCz5Qqc7x2eYCEXyMH4p6AYCG5EQMA4GA1UdDwEB/wQEAwIHgDAKBggqhkjOPQQDAwNnADBkAjB0oreRkNZ7AxdtICH6lkW8nERAwDPWP8w5BUSZL8sJ5KrootY9gevtIn1+FbFTJRACMAi8hy0yn0pO0Pl4wzCmgcRhpaPmsmeJ8j3bo573kh1MK4psbY2Q3swkNu+8QWmi3g=="));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("MIIDaDCCAu2gAwIBAgIUcYtX/2tpPlocI17Yh6PvUfQBDyYwCgYIKoZIzj0EAwMwgeAxCzAJBgNVBAYTAkJFMREwDwYDVQQHDAhCcnVzc2VsczEwMC4GA1UECgwnS2luZ2RvbSBvZiBCZWxnaXVtIC0gRmVkZXJhbCBHb3Zlcm5tZW50MTYwNAYDVQQLDC1GUFMgSG9tZSBBZmZhaXJzIC0gQklLLUdDSSAoTlRSQkUtMDM2MjQ3NTUzOCkxOTA3BgNVBAsMMEZQUyBQb2xpY3kgYW5kIFN1cHBvcnQgLSBCT1NBIChOVFJCRS0wNjcxNTE2NjQ3KTEZMBcGA1UEAwwQQmVsZ2l1bSBSb290IENBNjAeFw0yMDA2MDMxMDAxMzFaFw00MDA2MDMxMDAxMzFaMIHgMQswCQYDVQQGEwJCRTERMA8GA1UEBwwIQnJ1c3NlbHMxMDAuBgNVBAoMJ0tpbmdkb20gb2YgQmVsZ2l1bSAtIEZlZGVyYWwgR292ZXJubWVudDE2MDQGA1UECwwtRlBTIEhvbWUgQWZmYWlycyAtIEJJSy1HQ0kgKE5UUkJFLTAzNjI0NzU1MzgpMTkwNwYDVQQLDDBGUFMgUG9saWN5IGFuZCBTdXBwb3J0IC0gQk9TQSAoTlRSQkUtMDY3MTUxNjY0NykxGTAXBgNVBAMMEEJlbGdpdW0gUm9vdCBDQTYwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAR532ARaLVsPSf5Pz9+b5ExaxpCe8iGGkDgkbUlGM0ulbr0YqbKva7EoOAY+YL5ZJs8S0KIsuQNc0f2vgI8xcyPQHgeCaLcw0OzvmfCHf/OMOIozEKgKaAK6pHvaBXP0tijZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQEwHwYDVR0jBBgwFoAULqCIsAsNYonsHT/Un8ySRI5IaUYwHQYDVR0OBBYEFC6giLALDWKJ7B0/1J/MkkSOSGlGMA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAwNpADBmAjEAt2e2vVG4/aMjIokbQQuCnvI8so8rZl/IbKupMCJitfFi7oVlHllYFDdYMDTKWLZgAjEAsa2wuz3Ew6/68XXtIT+51snqkl2KLlaVgKXYlpTh2zqQBIBdKO1nMO/rQRfuZ701"));
        trustedCertificateSource.addCertificate(DSSUtils.loadCertificateFromBase64EncodedString("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"));
        certificateVerifier.setTrustedCertSources(trustedCertificateSource);
        return certificateVerifier;
    }

    @Override
    protected void checkEvidenceRecordType(EvidenceRecordWrapper evidenceRecord) {
        super.checkEvidenceRecordType(evidenceRecord);

        assertEquals(EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD, evidenceRecord.getEvidenceRecordType());
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecordWrapper = diagnosticData.getEvidenceRecords().get(0);
        List<XmlDigestMatcher> digestMatchers = evidenceRecordWrapper.getDigestMatchers();
        assertEquals(2, digestMatchers.size());

        boolean masterSigDMFound = false;
        boolean orphanRefDMFound = false;
        for (XmlDigestMatcher digestMatcher : digestMatchers) {
            if (DigestMatcherType.EVIDENCE_RECORD_MASTER_SIGNATURE == digestMatcher.getType()) {
                assertTrue(digestMatcher.isDataFound());
                assertTrue(digestMatcher.isDataIntact());
                masterSigDMFound = true;
            } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == digestMatcher.getType()) {
                assertFalse(digestMatcher.isDataFound());
                assertFalse(digestMatcher.isDataIntact());
                orphanRefDMFound = true;
            }
        }
        assertTrue(masterSigDMFound);
        assertTrue(orphanRefDMFound);
    }

    @Override
    protected void checkTimestamp(DiagnosticData diagnosticData, TimestampWrapper timestampWrapper) {
        assertNotNull(timestampWrapper.getProductionTime());
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertTrue(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid());
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 2;
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        super.verifySimpleReport(simpleReport);

        int sigWithErCounter = 0;
        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            if (Utils.isCollectionNotEmpty(signatureEvidenceRecords)) {
                ++sigWithErCounter;
            }

            XmlEvidenceRecord evidenceRecord = signatureEvidenceRecords.get(0);
            assertTrue(evidenceRecord.getAdESValidationDetails().getWarning().stream()
                    .noneMatch(m -> MessageTag.BBB_CV_ER_HASSDOC_ANS.getId().equals(m.getKey())));

        }
        assertEquals(1, sigWithErCounter);
    }

}

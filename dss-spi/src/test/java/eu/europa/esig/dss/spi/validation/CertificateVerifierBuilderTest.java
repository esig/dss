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
package eu.europa.esig.dss.spi.validation;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import eu.europa.esig.dss.spi.x509.revocation.crl.OfflineCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.OfflineOCSPSource;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CertificateVerifierBuilderTest {

    @Test
    public void buildCompleteCopyTest() {
        CertificateVerifier certificateVerifier = initCertificateVerifier();
        CertificateVerifier copy = new CertificateVerifierBuilder(certificateVerifier).buildCompleteCopy();
        assertEquals(certificateVerifier.getDefaultDigestAlgorithm(), copy.getDefaultDigestAlgorithm());
        assertEquals(certificateVerifier.getAIASource(), copy.getAIASource());
        assertEquals(certificateVerifier.getCrlSource(), copy.getCrlSource());
        assertEquals(certificateVerifier.getOcspSource(), copy.getOcspSource());
        assertEquals(certificateVerifier.getRevocationDataLoadingStrategyFactory(), copy.getRevocationDataLoadingStrategyFactory());
        assertEquals(certificateVerifier.isRevocationFallback(), copy.isRevocationFallback());
        assertEquals(certificateVerifier.getRevocationDataVerifier(), copy.getRevocationDataVerifier());
        assertEquals(certificateVerifier.isCheckRevocationForUntrustedChains(), copy.isCheckRevocationForUntrustedChains());
        assertEquals(certificateVerifier.getTimestampTokenVerifier(), copy.getTimestampTokenVerifier());
        assertEquals(certificateVerifier.isExtractPOEFromUntrustedChains(), copy.isExtractPOEFromUntrustedChains());
        assertEquals(certificateVerifier.getAdjunctCertSources(), copy.getAdjunctCertSources());
        assertEquals(certificateVerifier.getTrustedCertSources(), copy.getTrustedCertSources());
        assertEquals(certificateVerifier.getAlertOnInvalidSignature(), copy.getAlertOnInvalidSignature());
        assertEquals(certificateVerifier.getAlertOnInvalidTimestamp(), copy.getAlertOnInvalidTimestamp());
        assertEquals(certificateVerifier.getAlertOnMissingRevocationData(), copy.getAlertOnMissingRevocationData());
        assertEquals(certificateVerifier.getAlertOnNoRevocationAfterBestSignatureTime(), copy.getAlertOnNoRevocationAfterBestSignatureTime());
        assertEquals(certificateVerifier.getAlertOnRevokedCertificate(), copy.getAlertOnRevokedCertificate());
        assertEquals(certificateVerifier.getAlertOnUncoveredPOE(), copy.getAlertOnUncoveredPOE());
        assertEquals(certificateVerifier.getAlertOnExpiredSignature(), copy.getAlertOnExpiredSignature());
        assertEquals(certificateVerifier.getAlertOnExpiredCertificate(), copy.getAlertOnExpiredCertificate());
        assertEquals(certificateVerifier.getAlertOnNotYetValidCertificate(), copy.getAlertOnNotYetValidCertificate());
    }

    @Test
    public void buildOfflineAndSilentCopyTest() {
        CertificateVerifier certificateVerifier = initCertificateVerifier();
        certificateVerifier.setAlertOnInvalidSignature(new ExceptionOnStatusAlert());
        certificateVerifier.setAlertOnInvalidTimestamp(new ExceptionOnStatusAlert());
        certificateVerifier.setAlertOnMissingRevocationData(new ExceptionOnStatusAlert());
        certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new ExceptionOnStatusAlert());
        certificateVerifier.setAlertOnRevokedCertificate(new ExceptionOnStatusAlert());
        certificateVerifier.setAlertOnUncoveredPOE(new ExceptionOnStatusAlert());
        certificateVerifier.setAlertOnExpiredSignature(new ExceptionOnStatusAlert());
        certificateVerifier.setAlertOnExpiredCertificate(new ExceptionOnStatusAlert());
        certificateVerifier.setAlertOnNotYetValidCertificate(new ExceptionOnStatusAlert());

        CertificateVerifier copy = new CertificateVerifierBuilder(certificateVerifier).buildOfflineAndSilentCopy();

        assertEquals(certificateVerifier.getDefaultDigestAlgorithm(), copy.getDefaultDigestAlgorithm());
        assertEquals(certificateVerifier.getRevocationDataVerifier(), copy.getRevocationDataVerifier());
        assertEquals(certificateVerifier.isExtractPOEFromUntrustedChains(), copy.isExtractPOEFromUntrustedChains());
        assertEquals(certificateVerifier.getTimestampTokenVerifier(), copy.getTimestampTokenVerifier());
        assertEquals(certificateVerifier.getAdjunctCertSources(), copy.getAdjunctCertSources());
        assertEquals(certificateVerifier.getTrustedCertSources(), copy.getTrustedCertSources());
        assertNull(copy.getAIASource());
        assertNull(copy.getCrlSource());
        assertNull(copy.getOcspSource());
        assertNotNull(copy.getRevocationDataLoadingStrategyFactory()); // not relevant for offline validation
        assertFalse(copy.isRevocationFallback());
        assertFalse(copy.isCheckRevocationForUntrustedChains());
        assertTrue(copy.getAlertOnInvalidSignature() instanceof SilentOnStatusAlert);
        assertTrue(copy.getAlertOnInvalidTimestamp() instanceof SilentOnStatusAlert);
        assertTrue(copy.getAlertOnMissingRevocationData() instanceof SilentOnStatusAlert);
        assertTrue(copy.getAlertOnNoRevocationAfterBestSignatureTime() instanceof SilentOnStatusAlert);
        assertTrue(copy.getAlertOnRevokedCertificate() instanceof SilentOnStatusAlert);
        assertTrue(copy.getAlertOnUncoveredPOE() instanceof SilentOnStatusAlert);
        assertTrue(copy.getAlertOnExpiredSignature() instanceof SilentOnStatusAlert);
        assertTrue(copy.getAlertOnExpiredCertificate() instanceof SilentOnStatusAlert);
        assertTrue(copy.getAlertOnNotYetValidCertificate() instanceof SilentOnStatusAlert);
    }

    @Test
    public void buildCompleteCopyForValidationTest() {
        CertificateVerifier certificateVerifier = initCertificateVerifier();
        certificateVerifier.setRevocationFallback(false);

        CertificateVerifier copy = new CertificateVerifierBuilder(certificateVerifier).buildCompleteCopyForValidation();
        assertEquals(certificateVerifier.getDefaultDigestAlgorithm(), copy.getDefaultDigestAlgorithm());
        assertEquals(certificateVerifier.getAIASource(), copy.getAIASource());
        assertEquals(certificateVerifier.getCrlSource(), copy.getCrlSource());
        assertEquals(certificateVerifier.getOcspSource(), copy.getOcspSource());
        assertEquals(certificateVerifier.getRevocationDataLoadingStrategyFactory(), copy.getRevocationDataLoadingStrategyFactory());
        assertEquals(certificateVerifier.getRevocationDataVerifier(), copy.getRevocationDataVerifier());
        assertEquals(certificateVerifier.isCheckRevocationForUntrustedChains(), copy.isCheckRevocationForUntrustedChains());
        assertEquals(certificateVerifier.getTimestampTokenVerifier(), copy.getTimestampTokenVerifier());
        assertEquals(certificateVerifier.isExtractPOEFromUntrustedChains(), copy.isExtractPOEFromUntrustedChains());
        assertEquals(certificateVerifier.getAdjunctCertSources(), copy.getAdjunctCertSources());
        assertEquals(certificateVerifier.getTrustedCertSources(), copy.getTrustedCertSources());
        assertEquals(certificateVerifier.getAlertOnInvalidTimestamp(), copy.getAlertOnInvalidTimestamp());
        assertEquals(certificateVerifier.getAlertOnMissingRevocationData(), copy.getAlertOnMissingRevocationData());
        assertEquals(certificateVerifier.getAlertOnNoRevocationAfterBestSignatureTime(), copy.getAlertOnNoRevocationAfterBestSignatureTime());
        assertEquals(certificateVerifier.getAlertOnRevokedCertificate(), copy.getAlertOnRevokedCertificate());
        assertEquals(certificateVerifier.getAlertOnUncoveredPOE(), copy.getAlertOnUncoveredPOE());
        assertEquals(certificateVerifier.getAlertOnExpiredSignature(), copy.getAlertOnExpiredSignature());
        assertTrue(copy.isRevocationFallback());
    }

    private CertificateVerifier initCertificateVerifier() {
        CertificateVerifier certificateVerifier = new CommonCertificateVerifier();
        certificateVerifier.setDefaultDigestAlgorithm(DigestAlgorithm.SHA512);
        certificateVerifier.setAIASource(new DefaultAIASource());
        certificateVerifier.setCrlSource(new OfflineCRLSource() {
            private static final long serialVersionUID = 2488777601664014631L;
            @Override
            public List<RevocationToken<CRL>> getRevocationTokens(CertificateToken certificateToken, CertificateToken issuerToken) {
                return super.getRevocationTokens(certificateToken, issuerToken);
            }
        });
        certificateVerifier.setOcspSource(new OfflineOCSPSource() {
            private static final long serialVersionUID = 7607005228559280423L;

            @Override
            public List<RevocationToken<OCSP>> getRevocationTokens(CertificateToken certificate, CertificateToken issuer) {
                return super.getRevocationTokens(certificate, issuer);
            }
        });
        certificateVerifier.setRevocationDataLoadingStrategyFactory(new CRLFirstRevocationDataLoadingStrategyFactory());
        certificateVerifier.setRevocationDataVerifier(RevocationDataVerifier.createDefaultRevocationDataVerifier());
        certificateVerifier.setTimestampTokenVerifier(TimestampTokenVerifier.createDefaultTimestampTokenVerifier());
        certificateVerifier.setRevocationFallback(true);
        certificateVerifier.setCheckRevocationForUntrustedChains(true);
        certificateVerifier.setExtractPOEFromUntrustedChains(true);
        certificateVerifier.setAdjunctCertSources(new CommonCertificateSource());
        certificateVerifier.setTrustedCertSources(new CommonTrustedCertificateSource());
        certificateVerifier.setAlertOnInvalidTimestamp(new SilentOnStatusAlert());
        certificateVerifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());
        certificateVerifier.setAlertOnNoRevocationAfterBestSignatureTime(new SilentOnStatusAlert());
        certificateVerifier.setAlertOnRevokedCertificate(new SilentOnStatusAlert());
        certificateVerifier.setAlertOnUncoveredPOE(new SilentOnStatusAlert());
        certificateVerifier.setAlertOnExpiredSignature(new SilentOnStatusAlert());

        return certificateVerifier;
    }

}

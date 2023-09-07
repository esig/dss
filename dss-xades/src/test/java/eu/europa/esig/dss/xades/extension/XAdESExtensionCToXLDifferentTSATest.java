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
package eu.europa.esig.dss.xades.extension;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.FoundRevocationsProxy;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.RevocationOrigin;
import eu.europa.esig.dss.enumerations.RevocationRefOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.xades.signature.XAdESService;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

public class XAdESExtensionCToXLDifferentTSATest extends XAdESExtensionCToXLTest {

    @Override
    protected TSPSource getUsedTSPSourceAtSignatureTime() {
        return getAlternateGoodTsa();
    }

    @Override
    protected TSPSource getUsedTSPSourceAtExtensionTime() {
        return getGoodTsa();
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        return getCertificateVerifierWithSHA3_256();
    }

    @Override
    protected String getSigningAlias() {
        return RSA_SHA3_USER;
    }

    @Override
    protected void checkCertificates(DiagnosticData diagnosticData) {
        super.checkCertificates(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundCertificatesProxy foundCertificates = signature.foundCertificates();
        SignatureLevel signatureFormat = signature.getSignatureFormat();
        if (SignatureLevel.XAdES_C.equals(signatureFormat)) {
            assertEquals(3, foundCertificates.getRelatedCertificatesByRefOrigin(
                    CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());
            assertEquals(2, foundCertificates.getOrphanCertificatesByRefOrigin(
                    CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());
            assertEquals(0, foundCertificates.getRelatedCertificatesByOrigin(
                    CertificateOrigin.CERTIFICATE_VALUES).size());

        } else if (SignatureLevel.XAdES_XL.equals(signatureFormat)) {
            assertEquals(5, foundCertificates.getRelatedCertificatesByRefOrigin(
                    CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());
            assertEquals(0, foundCertificates.getOrphanCertificatesByRefOrigin(
                    CertificateRefOrigin.COMPLETE_CERTIFICATE_REFS).size());
            assertEquals(7, foundCertificates.getRelatedCertificatesByOrigin(
                    CertificateOrigin.CERTIFICATE_VALUES).size());

        } else {
            fail("Unexpected SignatureLevel reached : " + signatureFormat);
        }
    }

    @Override
    protected void checkRevocationData(DiagnosticData diagnosticData) {
        super.checkRevocationData(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundRevocationsProxy foundRevocations = signature.foundRevocations();
        SignatureLevel signatureFormat = signature.getSignatureFormat();
        if (SignatureLevel.XAdES_C.equals(signatureFormat)) {
            assertEquals(0, foundRevocations.getRelatedRevocationsByRefOrigin(
                    RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
            assertEquals(1, foundRevocations.getOrphanRevocationsByRefOrigin(
                    RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
            assertEquals(0, foundRevocations.getRelatedRevocationsByOrigin(
                    RevocationOrigin.REVOCATION_VALUES).size());

        } else if (SignatureLevel.XAdES_XL.equals(signatureFormat)) {
            assertEquals(1, foundRevocations.getRelatedRevocationsByRefOrigin(
                    RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
            assertEquals(0, foundRevocations.getOrphanRevocationsByRefOrigin(
                    RevocationRefOrigin.COMPLETE_REVOCATION_REFS).size());
            assertEquals(2, foundRevocations.getRelatedRevocationsByOrigin(
                    RevocationOrigin.REVOCATION_VALUES).size());

        } else {
            fail("Unexpected SignatureLevel reached : " + signatureFormat);
        }
    }
}

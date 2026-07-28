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
package eu.europa.esig.dss.cbades.signature;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.FoundCertificatesProxy;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateOrigin;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESLevelBEnvelopingNoKidTest extends AbstractCBAdESTestSignature {

    private DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> service;
    private DSSDocument documentToSign;

    private Date signingDate;

    @BeforeEach
    void init() throws Exception {
        service = new CBAdESService(getOfflineCertificateVerifier());
        documentToSign = new InMemoryDocument("Hello World!".getBytes(), "doc.txt");
        signingDate = new Date();
    }

    @Override
    protected CBAdESSignatureParameters getSignatureParameters() {
        CBAdESSignatureParameters signatureParameters = new CBAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingDate);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.CB_AdES_BASELINE_B);
        signatureParameters.setIncludeKeyIdentifier(false);
        return signatureParameters;
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        super.checkSigningCertificateValue(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        FoundCertificatesProxy foundCertificates = signature.foundCertificates();
        List<RelatedCertificateWrapper> signCerts = foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE);
        assertEquals(1, signCerts.size());

        List<CertificateRefWrapper> signCertReferences = signCerts.get(0).getReferences();
        assertEquals(1, signCertReferences.size());

        RelatedCertificateWrapper signingCertificate = null;
        for (RelatedCertificateWrapper certificateWrapper : signCerts) {
            assertTrue(Utils.isCollectionNotEmpty(certificateWrapper.getOrigins()));
            assertEquals(CertificateOrigin.KEY_INFO, certificateWrapper.getOrigins().get(0));
            if (signature.getSigningCertificate().getId().equals(certificateWrapper.getId())) {
                signingCertificate = certificateWrapper;
                break;
            }
        }
        assertNotNull(signingCertificate);

        boolean signCertFound = false;
        boolean keyIdentifierFound = false;
        for (CertificateRefWrapper certificateRefWrapper : signingCertificate.getReferences()) {
            if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRefWrapper.getOrigin())) {
                signCertFound = true;
            } else if (CertificateRefOrigin.KEY_IDENTIFIER.equals(certificateRefWrapper.getOrigin())) {
                keyIdentifierFound = true;
            }
        }
        assertTrue(signCertFound);
        assertFalse(keyIdentifierFound);

        assertEquals(0, foundCertificates.getRelatedCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size());
        assertEquals(0, foundCertificates.getOrphanCertificatesByRefOrigin(CertificateRefOrigin.KEY_IDENTIFIER).size());
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<CBAdESSignatureParameters, CBAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}

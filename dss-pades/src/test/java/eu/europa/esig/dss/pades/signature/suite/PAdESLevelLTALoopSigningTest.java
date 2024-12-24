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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;

import static org.junit.jupiter.api.Assertions.assertEquals;

// See DSS-3422. Manual testing
@Tag("slow")
public class PAdESLevelLTALoopSigningTest extends AbstractPAdESTestSignature {

    private static final int LOOPS = 15;

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument originalDocument;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        originalDocument = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        service = new PAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected DSSDocument sign() {
        documentToSign = originalDocument;
        DSSDocument signedDocument;
        for (int i = 0; i < LOOPS; i++) {
            signedDocument = super.sign();
            documentToSign = signedDocument;
        }

        awaitOneSecond(); // to update DSS dictionary

        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
        signedDocument = super.sign();

        documentToSign = originalDocument;
        return signedDocument;
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setCrlSource(pkiCRLSource());
        certificateVerifier.setOcspSource(pkiDelegatedOCSPSource());
        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(null);
        return certificateVerifier;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(16, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        int ltSignaturesCounter = 0;
        int ltaSignaturesCounter = 0;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (SignatureLevel.PAdES_BASELINE_LT.equals(signatureWrapper.getSignatureFormat())) {
                ++ltSignaturesCounter;
            } else if (SignatureLevel.PAdES_BASELINE_LTA.equals(signatureWrapper.getSignatureFormat())) {
                ++ltaSignaturesCounter;
            }
        }
        assertEquals(1, ltSignaturesCounter);
        assertEquals(15, ltaSignaturesCounter);
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}

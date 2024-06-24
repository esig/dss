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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.spi.x509.CommonCertificateSource;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class PDFNotAdESLevelBWithoutCertificatesTest extends AbstractPAdESTestSignature {

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        signatureParameters.setGenerateTBSWithoutCertificate(true);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        CommonCertificateSource signingCertificateSource = new CommonCertificateSource();
        signingCertificateSource.addCertificate(getSigningCert());
        validator.setSigningCertificateSource(signingCertificateSource);

        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();
        CommonCertificateSource adjunctCertificateSource = new CommonCertificateSource();
        for (CertificateToken certificateToken : getCertificateChain()) {
            adjunctCertificateSource.addCertificate(certificateToken);
        }
        certificateVerifier.addAdjunctCertSources(adjunctCertificateSource);
        validator.setCertificateVerifier(certificateVerifier);
        return validator;
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getSigningCertificateId(diagnosticData.getFirstSignatureId()));
        assertEquals(3, diagnosticData.getSignatureCertificateChain(diagnosticData.getFirstSignatureId()).size());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.PDF_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
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

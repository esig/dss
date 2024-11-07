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
package eu.europa.esig.dss.asic.xades.signature.asice;

import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEXAdESDoubleSignatureLTAAndLTTest extends AbstractASiCEXAdESTestSignature {

    private final DSSDocument ORIGINAL_DOC = new InMemoryDocument("Hello World !".getBytes(), "test.txt", MimeTypeEnum.TEXT);

    private CertificateVerifier certificateVerifier;
    private ASiCWithXAdESService service;
    private ASiCWithXAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private String signingAlias;

    @BeforeEach
    void init() throws Exception {
        certificateVerifier = getCompleteCertificateVerifier();
        service = new ASiCWithXAdESService(certificateVerifier);
        service.setTspSource(getGoodTsa());
    }

    @Override
    protected DSSDocument sign() {
        signingAlias = GOOD_USER;
        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        documentToSign = ORIGINAL_DOC;
        DSSDocument signedDocument = super.sign();

        signingAlias = RSA_SHA3_USER;
        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

        documentToSign = signedDocument;
        DSSDocument doubleSignedDocument = super.sign();
        assertNotNull(doubleSignedDocument);

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_T);

        documentToSign = signedDocument;
        doubleSignedDocument = super.sign();
        assertNotNull(doubleSignedDocument);

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LT);

        documentToSign = signedDocument;
        doubleSignedDocument = super.sign();
        assertNotNull(doubleSignedDocument);

        documentToSign = ORIGINAL_DOC;
        return doubleSignedDocument;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        boolean ltaSigFound = false;
        boolean ltSigFound = false;
        for (SignatureWrapper signature : diagnosticData.getSignatures()) {
            if (SignatureLevel.XAdES_BASELINE_LTA.equals(signature.getSignatureFormat())) {
                assertTrue(signature.isThereTLevel());
                assertTrue(signature.isThereALevel());
                ltaSigFound = true;
            } else if (SignatureLevel.XAdES_BASELINE_LT.equals(signature.getSignatureFormat())) {
                assertTrue(signature.isThereTLevel());
                assertFalse(signature.isThereALevel());
                ltSigFound = true;
            }
        }
        assertTrue(ltaSigFound);
        assertTrue(ltSigFound);
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkIssuerSigningCertificateValue(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        // skip
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected ASiCWithXAdESService getService() {
        return service;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
        return signatureParameters;
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}

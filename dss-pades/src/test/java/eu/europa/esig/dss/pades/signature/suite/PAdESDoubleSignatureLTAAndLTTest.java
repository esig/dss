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

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESExtensionService;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.timestamp.PAdESTimestampService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESDoubleSignatureLTAAndLTTest extends AbstractPAdESTestSignature {

    private DSSDocument originalDocument;

    private CertificateVerifier certificateVerifier;
    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private String signingAlias;

    @BeforeEach
    public void init() throws Exception {
        certificateVerifier = getCompleteCertificateVerifier();
        service = new PAdESService(certificateVerifier);
        service.setTspSource(getGoodTsa());

        originalDocument = new InMemoryDocument(PAdESDoubleSignatureTest.class.getResourceAsStream("/sample.pdf"));
    }

    @Override
    protected DSSDocument sign() {
        signingAlias = GOOD_USER;
        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);
        documentToSign = originalDocument;
        DSSDocument signedDocument = super.sign();

        signingAlias = RSA_SHA3_USER;
        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        documentToSign = signedDocument;
        DSSDocument doubleSignedDocument = super.sign();
        assertNotNull(doubleSignedDocument);

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        documentToSign = signedDocument;
        doubleSignedDocument = super.sign();
        assertNotNull(doubleSignedDocument);

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);

        documentToSign = doubleSignedDocument;
        Exception exception = assertThrows(AlertException.class, super::sign);
        assertTrue(exception.getMessage().contains("Error on signature augmentation to LT-level."));
        assertTrue(exception.getMessage().contains("The signature is already extended with a higher level."));

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new LogOnStatusAlert());

        DSSDocument tripleSignedDocument = super.sign();
        assertNotNull(tripleSignedDocument);

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new ExceptionOnStatusAlert());

        PAdESTimestampParameters timestampParameters = new PAdESTimestampParameters();
        PAdESTimestampService timestampService = new PAdESTimestampService(getGoodTsa());

        // continue with a double-signed doc
        DSSDocument timestampedDocument = timestampService.timestampDocument(doubleSignedDocument, timestampParameters);

        PAdESExtensionService extensionService = new PAdESExtensionService(getCompleteCertificateVerifier());
        DSSDocument extendedDocument = extensionService.incorporateValidationData(timestampedDocument);
        extendedDocument.setName(doubleSignedDocument.getName());

        documentToSign = originalDocument;
        return extendedDocument;
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
            if (SignatureLevel.PAdES_BASELINE_LTA.equals(signature.getSignatureFormat())) {
                assertTrue(signature.isThereTLevel());
                assertTrue(signature.isThereALevel());
                ltaSigFound = true;
            } else if (SignatureLevel.PAdES_BASELINE_LT.equals(signature.getSignatureFormat())) {
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
    protected DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        return signatureParameters;
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}

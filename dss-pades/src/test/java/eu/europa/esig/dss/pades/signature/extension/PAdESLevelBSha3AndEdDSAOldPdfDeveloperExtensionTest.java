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
package eu.europa.esig.dss.pades.signature.extension;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.AbstractPAdESTestSignature;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDocumentReader;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.fail;

public abstract class PAdESLevelBSha3AndEdDSAOldPdfDeveloperExtensionTest extends AbstractPAdESTestSignature {

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    private String signingAlias;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        signingAlias = RSA_SHA3_USER;

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA3_256);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument signedDocument = super.sign();

        signingAlias = ED25519_GOOD_USER;
        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setDigestAlgorithm(DigestAlgorithm.SHA512);

        documentToSign = signedDocument;
        return super.sign();
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);

        DSSDocument signedDocument = new InMemoryDocument(byteArray);
        try {
            PdfDocumentReader documentReader = getDocumentReader(signedDocument);
            PdfDict catalogDictionary = documentReader.getCatalogDictionary();
            PdfDict extensionsDict = catalogDictionary.getAsDict("Extensions");
            assertNull(extensionsDict);
        } catch (IOException e) {
            fail(e);
        }
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkDigestAlgorithm(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkEncryptionAlgorithm(DiagnosticData diagnosticData) {
        // skip
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
    protected void checkMessageDigestAlgorithm(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        // skip
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    protected abstract PdfDocumentReader getDocumentReader(DSSDocument document) throws IOException;

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
        return signingAlias;
    }

}

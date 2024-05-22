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
package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MultipleSignPadesBTest extends CookbookTools {

    private String signingAlias;

    @Test
    public void signPAdESBaselineB() throws Exception {

        // GET document to be signed -
        // Return DSSDocument toSignDocument
        preparePdfDoc();

        // Initialize a CertificateVerifier and a PAdESService
        CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
        PAdESService service = new PAdESService(commonCertificateVerifier);

        DSSDocument signedDocument;
        DSSDocument doubleSignedDocument;

        signingAlias = GOOD_USER;

        // tag::demo[]
        // import eu.europa.esig.dss.model.SignatureValue;
        // import eu.europa.esig.dss.model.ToBeSigned;
        // import eu.europa.esig.dss.pades.PAdESSignatureParameters;
        // import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
        // import eu.europa.esig.dss.token.SignatureTokenConnection;

        // Load the user token to create the first signature
        try (SignatureTokenConnection goodUserToken = getPkcs12Token()) {

            // Preparing parameters for the PAdES signature
            PAdESSignatureParameters parameters = initSignatureParameters();

            // Set the signing certificate and a certificate chain for the used token
            DSSPrivateKeyEntry privateKey = goodUserToken.getKeys().get(0);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());

            // Sign in three steps
            ToBeSigned dataToSign = service.getDataToSign(toSignDocument, parameters);
            SignatureValue signatureValue = goodUserToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
            signedDocument = service.signDocument(toSignDocument, parameters, signatureValue);
        }

        signingAlias = RSA_SHA3_USER;
        // Load the second user token
        try (SignatureTokenConnection rsaUserToken = getPkcs12Token()) {

            // Preparing parameters for the PAdES signature
            PAdESSignatureParameters parameters = initSignatureParameters();

            // Set the signing certificate and a certificate chain for the used token
            DSSPrivateKeyEntry privateKey = rsaUserToken.getKeys().get(0);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());

            // Sign in three steps using the document obtained after the first signature
            ToBeSigned dataToSign = service.getDataToSign(signedDocument, parameters);
            SignatureValue signatureValue = rsaUserToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);
            doubleSignedDocument = service.signDocument(signedDocument, parameters, signatureValue);

        }

        // end::demo[]

        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(doubleSignedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        Reports reports = validator.validateDocument();
        DiagnosticData diagnosticData = reports.getDiagnosticData();
        assertEquals(2, diagnosticData.getSignatures().size());

        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            assertTrue(signatureWrapper.isBLevelTechnicallyValid());
        }

    }

    private PAdESSignatureParameters initSignatureParameters() {
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        return parameters;
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}


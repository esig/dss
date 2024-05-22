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
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignProtectedPdfPadesBLevelTest extends CookbookTools {

    @Test
    public void signProtectedPdf() throws Exception {

        // GET document to be signed -
        DSSDocument protectedDocument = new FileDocument("src/test/resources/snippets/open_protected.pdf");

        try (SignatureTokenConnection signingToken = getPkcs12Token()) {
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            // tag::sign[]
            // import eu.europa.esig.dss.pades.PAdESSignatureParameters;

            // Preparing parameters for the PAdES signature
            PAdESSignatureParameters parameters = new PAdESSignatureParameters();
            // Provide a password for the protected document
            parameters.setPasswordProtection(new char[]{' '});
            // end::sign[]

            parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());

            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            PAdESService service = new PAdESService(commonCertificateVerifier);
            ToBeSigned dataToSign = service.getDataToSign(protectedDocument, parameters);
            DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
            SignatureValue signatureValue = signingToken.sign(dataToSign, digestAlgorithm, privateKey);
            assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, privateKey.getCertificate()));
            DSSDocument signedDocument = service.signDocument(protectedDocument, parameters, signatureValue);

            // tag::validate[]
            // import eu.europa.esig.dss.pades.validation.PDFDocumentValidator;
            // import eu.europa.esig.dss.validation.CommonCertificateVerifier;
            // import eu.europa.esig.dss.validation.reports.Reports;

            // Prepare DocumentValidator
            PDFDocumentValidator documentValidator = new PDFDocumentValidator(signedDocument);
            documentValidator.setCertificateVerifier(new CommonCertificateVerifier());
            // Provide a password for the protected document
            documentValidator.setPasswordProtection(new char[] { ' ' });
            // Validate
            Reports reports = documentValidator.validateDocument();
            // end::validate[]
            assertNotNull(reports);
        }

    }

}

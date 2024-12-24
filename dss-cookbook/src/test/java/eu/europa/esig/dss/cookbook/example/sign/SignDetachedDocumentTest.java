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
package eu.europa.esig.dss.cookbook.example.sign;

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.detailedreport.DetailedReport;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignDetachedDocumentTest extends CookbookTools {

    @Test
    void signWithDetachedDocTest() throws Exception {

        try (SignatureTokenConnection signingToken = getPkcs12Token()) {

            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);

            DSSDocument originalDocument = new InMemoryDocument("Hello World!".getBytes());

            // tag::demo[]
            // import eu.europa.esig.dss.cades.CAdESSignatureParameters;
            // import eu.europa.esig.dss.cades.signature.CAdESService;
            // import eu.europa.esig.dss.model.DSSDocument;
            // import eu.europa.esig.dss.model.DigestDocument;
            // import eu.europa.esig.dss.model.SignatureValue;
            // import eu.europa.esig.dss.model.ToBeSigned;
            // import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
            // import eu.europa.esig.dss.validation.DocumentValidator;
            // import eu.europa.esig.dss.validation.reports.Reports;
            // import java.util.Arrays;

            // Create a DigestDocument from original DSSDocument
            DigestDocument digestDocument = new DigestDocument();
            digestDocument.addDigest(DigestAlgorithm.SHA256, originalDocument.getDigestValue(DigestAlgorithm.SHA256));

            // Preparing parameters for a signature creation
            CAdESSignatureParameters parameters = new CAdESSignatureParameters();
            parameters.setSigningCertificate(privateKey.getCertificate());
            parameters.setCertificateChain(privateKey.getCertificateChain());
            parameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);

            // Set the detached packaging, as a digest only will be included into the signature, and the original content
            parameters.setSignaturePackaging(SignaturePackaging.DETACHED);

            // The same DigestAlgorithm shall be used as the one used to create the DigestDocument
            parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

            // Create common certificate verifier
            CommonCertificateVerifier commonCertificateVerifier = new CommonCertificateVerifier();
            // Create signature service for signature creation
            CAdESService service = new CAdESService(commonCertificateVerifier);

            // Get the SignedInfo segment that need to be signed providing the digest document
            ToBeSigned dataToSign = service.getDataToSign(digestDocument, parameters);

            // Sign the ToBeSigned data
            SignatureValue signatureValue = signingToken.sign(dataToSign, parameters.getDigestAlgorithm(), privateKey);

            // We invoke the signature service to create a signed document incorporating the obtained Sig
            DSSDocument signedDocument = service.signDocument(digestDocument, parameters, signatureValue);

            // Initialize the DocumentValidator
            DocumentValidator documentValidator = SignedDocumentValidator.fromDocument(signedDocument);

            // Set the CertificateVerifier
            documentValidator.setCertificateVerifier(commonCertificateVerifier);

            // Provide the original or digested document as a detached contents to the validator
            documentValidator.setDetachedContents(Arrays.asList(originalDocument));

            // Validate the signed document
            Reports reports = documentValidator.validateDocument();

            // end::demo[]

            assertNotNull(reports);

            SimpleReport simpleReport = reports.getSimpleReport();
            DetailedReport detailedReport = reports.getDetailedReport();
            DiagnosticData diagnosticData = reports.getDiagnosticData();
            assertNotNull(simpleReport);
            assertNotNull(detailedReport);
            assertNotNull(diagnosticData);

            assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
        }
    }
}

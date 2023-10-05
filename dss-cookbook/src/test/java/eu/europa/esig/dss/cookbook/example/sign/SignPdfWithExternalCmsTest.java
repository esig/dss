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

import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.cookbook.example.CookbookTools;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.pades.signature.PAdESWithExternalCMSService;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.SignatureTokenConnection;
import eu.europa.esig.dss.validation.CertificateVerifier;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SignPdfWithExternalCmsTest extends CookbookTools {

    @Test
    public void test() throws Exception {
        preparePdfDoc();

        // tag::demo-pdf-sign[]
        // import eu.europa.esig.dss.enumerations.SignatureLevel;
        // import eu.europa.esig.dss.model.DSSDocument;
        // import eu.europa.esig.dss.pades.PAdESSignatureParameters;
        // import eu.europa.esig.dss.pades.signature.PAdESWithExternalCMSService;
        // import eu.europa.esig.dss.model.DSSMessageDigest;

        // Instantiate PDF signature service using external CMS
        PAdESWithExternalCMSService service = new PAdESWithExternalCMSService();

        // Configure signature parameters
        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.setReason("DSS testing");

        // Prepare the PDF signature revision and compute message-digest of the byte range content
        DSSMessageDigest messageDigest = service.getMessageDigest(toSignDocument, signatureParameters);
        assertNotNull(messageDigest);

        // Obtain CMS signature from external CMS signature provider
        DSSDocument cmsSignature = getExternalCMSSignature(messageDigest);
        assertNotNull(cmsSignature);

        // Optional : verify validity of the obtained CMS signature
        assertTrue(service.isValidCMSSignedData(messageDigest, cmsSignature));
        assertTrue(service.isValidPAdESBaselineCMSSignedData(messageDigest, cmsSignature));

        // Embed the obtained CMS signature to a PDF document with prepared signature revision
        DSSDocument signedDocument = service.signDocument(toSignDocument, signatureParameters, cmsSignature);
        // end::demo-pdf-sign[]

        DiagnosticData diagnosticData = testFinalDocument(signedDocument);
        assertEquals(SignatureLevel.PAdES_BASELINE_B, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
        assertTrue(diagnosticData.isBLevelTechnicallyValid(diagnosticData.getFirstSignatureId()));
    }

    private CMSSignedDocument getExternalCMSSignature(DSSMessageDigest messageDigest) throws Exception {
        CertificateVerifier certificateVerifier = getOfflineCertificateVerifier();

        // tag::demo-cms-sign[]
        // import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
        // import eu.europa.esig.dss.enumerations.SignatureLevel;
        // import eu.europa.esig.dss.model.SignatureValue;
        // import eu.europa.esig.dss.model.ToBeSigned;
        // import eu.europa.esig.dss.pades.PAdESSignatureParameters;
        // import eu.europa.esig.dss.pades.signature.ExternalCMSService;
        // import java.util.Date;

        // Instantiate CMS generation service for PAdES signature creation
        ExternalCMSService padesCMSGeneratorService = new ExternalCMSService(certificateVerifier);

        // Configure signature parameters
        // NOTE: parameters concern only CMS signature creation, but the signature level shall correspond
        // to the target level of a PAdES signature
        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        // Create DTBS (data to be signed) using the message-digest of a PDF signature byte range obtained from a client
        ToBeSigned dataToSign = padesCMSGeneratorService.getDataToSign(messageDigest, signatureParameters);

        // Sign the DTBS using a private key connection or remote-signing service
        SignatureValue signatureValue = computeSignatureValue(dataToSign, signatureParameters.getDigestAlgorithm());

        // Create a CMS signature using the provided message-digest, signature parameters and the signature value
        CMSSignedDocument cmsSignature = padesCMSGeneratorService.signMessageDigest(messageDigest, signatureParameters, signatureValue);
        // end::demo-cms-sign[]
        assertNotNull(cmsSignature);

        return cmsSignature;
    }

    private SignatureValue computeSignatureValue(ToBeSigned toBeSigned, DigestAlgorithm digestAlgorithm) throws Exception {
        try (SignatureTokenConnection signingToken = getToken()) {
            DSSPrivateKeyEntry privateKey = signingToken.getKeys().get(0);
            return signingToken.sign(toBeSigned, digestAlgorithm, privateKey);
        }
    }

}

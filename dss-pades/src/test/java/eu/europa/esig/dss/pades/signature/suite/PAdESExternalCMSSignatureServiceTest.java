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

import eu.europa.esig.dss.cades.CAdESSignatureParameters;
import eu.europa.esig.dss.cades.signature.CAdESService;
import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.pades.signature.PAdESWithExternalCMSService;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESExternalCMSSignatureServiceTest extends PKIFactoryAccess {

    @Test
    void test() {
        PAdESWithExternalCMSService service = new PAdESWithExternalCMSService();

        Exception exception = assertThrows(NullPointerException.class, () ->
                service.getMessageDigest(null, null));
        assertEquals("toSignDocument cannot be null!", exception.getMessage());

        DSSDocument documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));
        DigestDocument digestDocument = new DigestDocument(DigestAlgorithm.SHA512, documentToSign.getDigestValue(DigestAlgorithm.SHA512));

        exception = assertThrows(NullPointerException.class, () ->
                service.getMessageDigest(digestDocument, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());

        PAdESSignatureParameters parameters = new PAdESSignatureParameters();

        exception = assertThrows(IllegalArgumentException.class, () ->
                service.getMessageDigest(digestDocument, parameters));
        assertEquals("DigestDocument cannot be used! PDF document is expected!", exception.getMessage());

        DSSMessageDigest messageDigest = service.getMessageDigest(documentToSign, parameters);
        assertNotNull(messageDigest);
        assertEquals(parameters.getDigestAlgorithm(), messageDigest.getAlgorithm());
        assertTrue(Utils.isArrayNotEmpty(messageDigest.getValue()));


        exception = assertThrows(NullPointerException.class, () ->
                service.isValidCMSSignedData(null, null));
        assertEquals("messageDigest shall be provided!", exception.getMessage());
        exception = assertThrows(NullPointerException.class, () ->
                service.isValidCMSSignedData(messageDigest, null));
        assertEquals("CMSSignedDocument shall be provided!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                service.isValidPAdESBaselineCMSSignedData(null, null));
        assertEquals("messageDigest shall be provided!", exception.getMessage());
        exception = assertThrows(NullPointerException.class, () ->
                service.isValidPAdESBaselineCMSSignedData(messageDigest, null));
        assertEquals("CMSSignedDocument shall be provided!", exception.getMessage());

        assertFalse(service.isValidCMSSignedData(messageDigest, documentToSign));
        assertFalse(service.isValidCMSSignedData(messageDigest, digestDocument));
        assertFalse(service.isValidPAdESBaselineCMSSignedData(messageDigest, documentToSign));
        assertFalse(service.isValidPAdESBaselineCMSSignedData(messageDigest, digestDocument));

        CAdESSignatureParameters cadesParameters = new CAdESSignatureParameters();
        cadesParameters.setSigningCertificate(getSigningCert());
        cadesParameters.setCertificateChain(getCertificateChain());
        cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        cadesParameters.setSignaturePackaging(SignaturePackaging.DETACHED);

        DigestDocument digestDocumentToSign = DSSUtils.toDigestDocument(messageDigest);
        CAdESService cadesService = new CAdESService(getOfflineCertificateVerifier());
        ToBeSigned dataToSign = cadesService.getDataToSign(digestDocumentToSign, cadesParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, messageDigest.getAlgorithm(), getPrivateKeyEntry());
        DSSDocument cadesDetachedSignature = cadesService.signDocument(digestDocumentToSign, cadesParameters, signatureValue);

        assertFalse(service.isValidCMSSignedData(new DSSMessageDigest(digestDocument.getExistingDigest()), cadesDetachedSignature));
        assertTrue(service.isValidCMSSignedData(messageDigest, cadesDetachedSignature));

        assertFalse(service.isValidPAdESBaselineCMSSignedData(messageDigest, cadesDetachedSignature));


        PAdESSignatureParameters cmsParameters = new PAdESSignatureParameters();
        cmsParameters.setSigningCertificate(getSigningCert());
        cmsParameters.setCertificateChain(getCertificateChain());
        cmsParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        ExternalCMSService cmsGeneratorService = new ExternalCMSService(getOfflineCertificateVerifier());
        dataToSign = cmsGeneratorService.getDataToSign(messageDigest, cmsParameters);
        signatureValue = getToken().sign(dataToSign, messageDigest.getAlgorithm(), getPrivateKeyEntry());
        CMSSignedDocument cmsSignature = cmsGeneratorService.signMessageDigest(messageDigest, cmsParameters, signatureValue);

        assertFalse(service.isValidCMSSignedData(new DSSMessageDigest(digestDocument.getExistingDigest()), cmsSignature));
        assertTrue(service.isValidCMSSignedData(messageDigest, cmsSignature));

        assertTrue(service.isValidPAdESBaselineCMSSignedData(messageDigest, cmsSignature));

        cadesParameters = new CAdESSignatureParameters();
        cadesParameters.setSigningCertificate(getSigningCert());
        cadesParameters.setCertificateChain(getCertificateChain());
        cadesParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        cadesParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
        cadesParameters.setDetachedContents(Collections.singletonList(new DigestDocument(messageDigest.getAlgorithm(), messageDigest.getValue())));

        dataToSign = cadesService.getDataToSign(cmsSignature, cadesParameters);
        signatureValue = getToken().sign(dataToSign, messageDigest.getAlgorithm(), getPrivateKeyEntry());
        DSSDocument doubleSignedCms = cadesService.signDocument(cmsSignature, cadesParameters, signatureValue);
        assertFalse(service.isValidCMSSignedData(messageDigest, doubleSignedCms));

        exception = assertThrows(NullPointerException.class, () ->
                service.signDocument(null, null, null));
        assertEquals("toSignDocument cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                service.signDocument(digestDocument, null, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                service.signDocument(digestDocument, parameters, null));
        assertEquals("SignatureLevel shall be defined within parameters!", exception.getMessage());

        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        exception = assertThrows(NullPointerException.class, () ->
                service.signDocument(digestDocument, parameters, null));
        assertEquals("CMSDocument cannot be null!", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () ->
                service.signDocument(digestDocument, parameters, digestDocument));
        assertEquals("DigestDocument cannot be used! PDF document is expected!", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () ->
                service.signDocument(documentToSign, parameters, digestDocument));
        assertEquals("DigestDocument is not allowed for current operation!", exception.getMessage());

        DSSDocument signedDocument = service.signDocument(documentToSign, parameters, cmsSignature);
        assertNotNull(signedDocument);
        validate(signedDocument, SignatureLevel.PAdES_BASELINE_B);

        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

        exception = assertThrows(NullPointerException.class, () ->
                service.signDocument(documentToSign, parameters, cmsSignature));
        assertEquals("CertificateVerifier shall be provided for PAdES extension!", exception.getMessage());

        service.setCertificateVerifier(getOfflineCertificateVerifier());
        exception = assertThrows(NullPointerException.class, () ->
                service.signDocument(documentToSign, parameters, cmsSignature));
        assertEquals("TSPSource shall be provided for PAdES extension!", exception.getMessage());

        service.setTspSource(getGoodTsa());
        signedDocument = service.signDocument(documentToSign, parameters, cmsSignature);
        assertNotNull(signedDocument);
        validate(signedDocument, SignatureLevel.PAdES_BASELINE_T);
    }

    private void validate(DSSDocument documentToValidate, SignatureLevel expectedSignatureLevel) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToValidate);
        validator.setCertificateVerifier(getCompleteCertificateVerifier());

        Reports reports = validator.validateDocument();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.TOTAL_PASSED, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(expectedSignatureLevel, simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        for (TimestampWrapper timestamp : timestampList) {
            assertTrue(timestamp.isSignatureValid());
            assertTrue(timestamp.isSignatureIntact());
            assertTrue(timestamp.isMessageImprintDataFound());
            assertTrue(timestamp.isMessageImprintDataIntact());
        }
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}

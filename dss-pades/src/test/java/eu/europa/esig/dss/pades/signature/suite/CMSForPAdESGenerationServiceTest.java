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

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.cades.signature.CMSSignedDocument;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.ExternalCMSService;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.model.DSSMessageDigest;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CMSForPAdESGenerationServiceTest extends PKIFactoryAccess {

    @Test
    public void test() {
        ExternalCMSService service = new ExternalCMSService(getOfflineCertificateVerifier());

        DSSDocument toSignDocument = new InMemoryDocument("Hello World!".getBytes());
        DSSMessageDigest messageDigest = new DSSMessageDigest(DigestAlgorithm.SHA256, toSignDocument.getDigestValue(DigestAlgorithm.SHA256));
        PAdESSignatureParameters parameters = new PAdESSignatureParameters();
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA512);

        Exception exception = assertThrows(NullPointerException.class, () ->
                service.getDataToSign(null, null));
        assertEquals("messageDigest cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                service.getDataToSign(messageDigest, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                service.getDataToSign(messageDigest, parameters));
        assertEquals("SignatureLevel shall be defined!", exception.getMessage());

        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
        exception = assertThrows(IllegalArgumentException.class, () ->
                service.getDataToSign(messageDigest, parameters));
        assertEquals("SignatureLevel 'PAdES-BASELINE-LT' is not supported within PAdESCMSGeneratorService!",
                exception.getMessage());

        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        exception = assertThrows(IllegalArgumentException.class, () ->
                service.getDataToSign(messageDigest, parameters));
        assertEquals("Signing Certificate is not defined! Set signing certificate or " +
                "use method setGenerateTBSWithoutCertificate(true).", exception.getMessage());

        parameters.setSigningCertificate(getCertificate(NOT_YET_VALID_USER));
        exception = assertThrows(AlertException.class, () ->
                service.getDataToSign(messageDigest, parameters));
        assertTrue(exception.getMessage().contains("Error on signature creation"));
        assertTrue(exception.getMessage().contains("is not yet valid at signing time"));

        parameters.setSigningCertificate(getCertificate(EXPIRED_USER));
        exception = assertThrows(AlertException.class, () ->
                service.getDataToSign(messageDigest, parameters));
        assertTrue(exception.getMessage().contains("Error on signature creation"));
        assertTrue(exception.getMessage().contains("is expired at signing time"));

        parameters.setSigningCertificate(getSigningCert());
        exception = assertThrows(IllegalArgumentException.class, () ->
                service.getDataToSign(messageDigest, parameters));
        assertEquals("The DigestAlgorithm provided within Digest 'SHA256' " +
                "does not correspond to the one defined in SignatureParameters 'SHA512'!", exception.getMessage());

        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        ToBeSigned dataToSign = service.getDataToSign(messageDigest, parameters);
        assertNotNull(dataToSign);
        assertTrue(Utils.isArrayNotEmpty(dataToSign.getBytes()));


        SignatureValue signatureValue = getToken().sign(dataToSign, parameters.getDigestAlgorithm(), getPrivateKeyEntry());
        assertNotNull(signatureValue);
        PAdESService padesService = new PAdESService(getOfflineCertificateVerifier());
        assertTrue(padesService.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));


        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        exception = assertThrows(NullPointerException.class, () ->
                service.signMessageDigest(null, null, null));
        assertEquals("messageDigest cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                service.signMessageDigest(messageDigest, null, null));
        assertEquals("SignatureParameters cannot be null!", exception.getMessage());

        exception = assertThrows(NullPointerException.class, () ->
                service.signMessageDigest(messageDigest, parameters, null));
        assertEquals("SignatureValue cannot be null!", exception.getMessage());

        exception = assertThrows(IllegalArgumentException.class, () ->
                service.signMessageDigest(messageDigest, parameters, signatureValue));
        assertEquals("SignatureLevel 'PAdES-BASELINE-LTA' is not supported within PAdESCMSGeneratorService!",
                exception.getMessage());

        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        CMSSignedDocument cmsSignature = service.signMessageDigest(messageDigest, parameters, signatureValue);
        assertNotNull(cmsSignature);
        validate(cmsSignature, toSignDocument, SignatureLevel.CAdES_BES);

        parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);
        exception = assertThrows(NullPointerException.class, () ->
                service.signMessageDigest(messageDigest, parameters, signatureValue));
        assertEquals("TSPSource shall be provided for T-level creation!",
                exception.getMessage());

        service.setTspSource(getGoodTsa());
        cmsSignature = service.signMessageDigest(messageDigest, parameters, signatureValue);
        assertNotNull(cmsSignature);
        validate(cmsSignature, toSignDocument, SignatureLevel.CAdES_T);
    }

    private void validate(DSSDocument documentToValidate, DSSDocument detachedDocument, SignatureLevel expectedSignatureLevel) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(documentToValidate);
        validator.setCertificateVerifier(getCompleteCertificateVerifier());
        validator.setDetachedContents(Collections.singletonList(detachedDocument));

        Reports reports = validator.validateDocument();
        SimpleReport simpleReport = reports.getSimpleReport();
        assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(simpleReport.getFirstSignatureId()));
        assertEquals(SubIndication.SIG_CONSTRAINTS_FAILURE, simpleReport.getSubIndication(simpleReport.getFirstSignatureId()));
        assertEquals(expectedSignatureLevel, simpleReport.getSignatureFormat(simpleReport.getFirstSignatureId()));

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.isBLevelTechnicallyValid());

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

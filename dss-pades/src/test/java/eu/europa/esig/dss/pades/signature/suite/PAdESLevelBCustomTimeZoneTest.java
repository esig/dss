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
package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.TimeZone;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PAdESLevelBCustomTimeZoneTest extends AbstractPAdESTestSignature {

    private static final TimeZone DEFAULT_TIME_ZONE = TimeZone.getDefault();

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new InMemoryDocument(PAdESLevelBCustomTimeZoneTest.class.getResourceAsStream("/sample.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningTimeZone(TimeZone.getTimeZone("GMT+3"));

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @AfterEach
    void afterEach() {
        TimeZone.setDefault(DEFAULT_TIME_ZONE);
    }

    @Override
    protected void onDocumentSigned(byte[] byteArray) {
        super.onDocumentSigned(byteArray);
        assertTrue(new String(byteArray).contains("+03'00'"));
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

    @Test
    void changeParametersTimeZoneTest() {
        Date signingTime = new Date();

        PAdESSignatureParameters signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.bLevel().setSigningDate(signingTime);
        signatureParameters.setSigningTimeZone(TimeZone.getTimeZone("GMT+3"));

        ToBeSigned dataToSign = service.getDataToSign(getDocumentToSign(), signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.bLevel().setSigningDate(signingTime);
        signatureParameters.setSigningTimeZone(TimeZone.getTimeZone("GMT+0"));

        DSSDocument signedDocument = service.signDocument(getDocumentToSign(), signatureParameters, signatureValue);

        SignedDocumentValidator validator = getValidator(signedDocument);
        Reports reports = validator.validateDocument();

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isSignatureIntact());
        assertFalse(signature.isSignatureValid());
    }

    @Test
    void changeSystemTimeZoneTest() {
        TimeZone.setDefault(TimeZone.getTimeZone("GMT+3"));
        PAdESSignatureParameters signatureParameters = getSignatureParameters();

        ToBeSigned dataToSign = service.getDataToSign(getDocumentToSign(), signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());

        TimeZone.setDefault(TimeZone.getTimeZone("GMT+0"));
        DSSDocument signedDocument = service.signDocument(getDocumentToSign(), signatureParameters, signatureValue);

        SignedDocumentValidator validator = getValidator(signedDocument);
        Reports reports = validator.validateDocument();

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.isSignatureIntact());
        assertTrue(signature.isSignatureValid());
    }

    @Test
    void defaultTimeZoneChangeSystemTimeZoneTest() {
        TimeZone.setDefault(TimeZone.getTimeZone("GMT+3"));
        PAdESSignatureParameters signatureParameters = getSignatureParameters();
        signatureParameters.setSigningTimeZone(DEFAULT_TIME_ZONE);

        ToBeSigned dataToSign = service.getDataToSign(getDocumentToSign(), signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(), getPrivateKeyEntry());

        TimeZone.setDefault(TimeZone.getTimeZone("GMT+0"));
        DSSDocument signedDocument = service.signDocument(getDocumentToSign(), signatureParameters, signatureValue);

        SignedDocumentValidator validator = getValidator(signedDocument);
        Reports reports = validator.validateDocument();

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.isSignatureIntact());
        assertTrue(signature.isSignatureValid());
    }

}

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
package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.CertificateRevocationWrapper;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.RevocationType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.test.PKIFactoryAccess;
import eu.europa.esig.dss.validation.CRLFirstRevocationDataLoadingStrategy;
import eu.europa.esig.dss.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.DocumentValidator;
import eu.europa.esig.dss.validation.OCSPFirstRevocationDataLoadingStrategy;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.dss.xades.XAdESSignatureParameters;
import eu.europa.esig.dss.xades.signature.XAdESService;
import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESOCSPVsCRLValidationTest extends PKIFactoryAccess {

    @Test
    public void test() {
        DSSDocument documentToSign = new FileDocument("src/test/resources/sample.xml");

        XAdESSignatureParameters signatureParameters = new XAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);
        signatureParameters.bLevel().setSigningDate(new Date());

        XAdESService service = new XAdESService(getOfflineCertificateVerifier());

        ToBeSigned dataToSign = service.getDataToSign(documentToSign, signatureParameters);
        SignatureValue signatureValue = getToken().sign(dataToSign, signatureParameters.getDigestAlgorithm(),
                signatureParameters.getMaskGenerationFunction(), getPrivateKeyEntry());
        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));
        DSSDocument signedDocument = service.signDocument(documentToSign, signatureParameters, signatureValue);

        CertificateVerifier certificateVerifier = getCompleteCertificateVerifier();

        DocumentValidator validator = SignedDocumentValidator.fromDocument(signedDocument);
        certificateVerifier.setRevocationDataLoadingStrategy(new OCSPFirstRevocationDataLoadingStrategy());
        validator.setCertificateVerifier(certificateVerifier);
        Reports reports = validator.validateDocument();

        DiagnosticData diagnosticData = reports.getDiagnosticData();
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        CertificateWrapper signingCertificate = signature.getSigningCertificate();
        List<CertificateRevocationWrapper> certificateRevocationData = signingCertificate.getCertificateRevocationData();
        assertEquals(1, certificateRevocationData.size());
        assertEquals(RevocationType.OCSP, certificateRevocationData.get(0).getRevocationType());

        validator = SignedDocumentValidator.fromDocument(signedDocument);
        certificateVerifier.setRevocationDataLoadingStrategy(new CRLFirstRevocationDataLoadingStrategy());
        validator.setCertificateVerifier(certificateVerifier);
        reports = validator.validateDocument();

        diagnosticData = reports.getDiagnosticData();
        signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        signingCertificate = signature.getSigningCertificate();
        certificateRevocationData = signingCertificate.getCertificateRevocationData();
        assertEquals(1, certificateRevocationData.size());
        assertEquals(RevocationType.CRL, certificateRevocationData.get(0).getRevocationType());
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER_WITH_CRL_AND_OCSP;
    }

}

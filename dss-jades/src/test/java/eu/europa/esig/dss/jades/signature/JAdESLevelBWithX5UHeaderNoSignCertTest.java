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
package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.CertificateRefWrapper;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.RelatedCertificateWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.CertificateRefOrigin;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESTimestampParameters;
import eu.europa.esig.dss.jades.validation.CommonX509URLCertificateSource;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.spi.signature.AdvancedSignature;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.io.File;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class JAdESLevelBWithX5UHeaderNoSignCertTest extends AbstractJAdESTestSignature {

    private static final String X509_URL = "http://nowina.lu/cert-uri";

    private DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> service;
    private DSSDocument documentToSign;
    private JAdESSignatureParameters signatureParameters;

    @BeforeEach
    public void init() {
        service = new JAdESService(getCompleteCertificateVerifier());
        documentToSign = new FileDocument(new File("src/test/resources/sample.json"));
        signatureParameters = new JAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        signatureParameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);

        signatureParameters.setGenerateTBSWithoutCertificate(true);
        signatureParameters.setX509Url(X509_URL);
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        SignedDocumentValidator validator = super.getValidator(signedDocument);
        validator.setCertificateVerifier(getCompleteCertificateVerifier());
        CommonX509URLCertificateSource signingCertificateSource = new CommonX509URLCertificateSource();

        Exception exception = assertThrows(UnsupportedOperationException.class,
                () -> signingCertificateSource.addCertificate(getSigningCert()));
        assertEquals("#addCertificate(certificateToAdd) method is not supported in CommonX509URLCertificateSource! " +
                "Please use #addCertificate(uri, certificateToAdd) or #addCertificates(uri, certificatesToAdd) methods.", exception.getMessage());

        signingCertificateSource.addCertificate(X509_URL, getSigningCert());

        validator.setSigningCertificateSource(signingCertificateSource);
        return validator;
    }

    @Override
    protected void verifySourcesAndDiagnosticData(List<AdvancedSignature> advancedSignatures,
                                                  DiagnosticData diagnosticData) {
        AdvancedSignature advancedSignature = advancedSignatures.get(0);
        assertEquals(1, advancedSignature.getCertificates().size());

        SignatureWrapper signatureWrapper = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());

        List<RelatedCertificateWrapper> relatedCertificates = signatureWrapper.foundCertificates().getRelatedCertificates();
        assertEquals(1, relatedCertificates.size());

        int signCertCounter = 0;
        int x5uCertCounter = 0;
        for (RelatedCertificateWrapper relatedCertificate : relatedCertificates) {
            assertFalse(Utils.isCollectionNotEmpty(relatedCertificate.getOrigins()));
            for (CertificateRefWrapper certificateRef : relatedCertificate.getReferences()) {
                if (CertificateRefOrigin.SIGNING_CERTIFICATE.equals(certificateRef.getOrigin())) {
                    ++signCertCounter;
                } else if (CertificateRefOrigin.X509_URL.equals(certificateRef.getOrigin())) {
                    ++x5uCertCounter;
                }
            }
        }
        assertEquals(0, signCertCounter);
        assertEquals(1, x5uCertCounter);

        assertEquals(0, signatureWrapper.foundCertificates().getRelatedCertificatesByRefOrigin(CertificateRefOrigin.SIGNING_CERTIFICATE).size());
        assertEquals(1, signatureWrapper.foundCertificates().getRelatedCertificatesByRefOrigin(CertificateRefOrigin.X509_URL).size());

        assertNotNull(signatureWrapper.getSigningCertificate());
        assertEquals(3, Utils.collectionSize(signatureWrapper.getCertificateChain()));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.JSON_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isStructuralValidationValid());
    }

    @Override
    protected void checkSigningCertificateValue(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isSigningCertificateIdentified());
        assertFalse(signature.isSigningCertificateReferencePresent());
        assertFalse(signature.isSigningCertificateReferenceUnique());
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<JAdESSignatureParameters, JAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}

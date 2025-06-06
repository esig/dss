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
package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.alert.LogOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCECAdESDoubleSignatureOnExpiredNoPOETest extends AbstractASiCECAdESTestSignature {

    private String signingAlias;
    private DSSDocument originalDocument;

    private DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;
    private CertificateVerifier certificateVerifier;

    private Date signingTime;

    @BeforeEach
    void init() throws Exception {
        certificateVerifier = getCompleteCertificateVerifier();
        service = new ASiCWithCAdESService(certificateVerifier);

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.MONTH, -2);
        signingTime = calendar.getTime();

        originalDocument = new InMemoryDocument("Hello World !".getBytes(), "test.txt", MimeTypeEnum.TEXT);

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);
    }

    @Override
    protected DSSDocument sign() {
        signingAlias = EXPIRED_USER;

        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        documentToSign = originalDocument;
        DSSDocument signedDocument = super.sign();

        documentToSign = signedDocument;

        signingAlias = GOOD_USER;
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        service.setTspSource(getGoodTsa());
        signingTime = new Date();

        Exception exception = assertThrows(AlertException.class, super::sign);
        assertTrue(exception.getMessage().contains("Error on signature augmentation"));
        assertTrue(exception.getMessage().contains("Expired signature found"));

        certificateVerifier.setAlertOnExpiredCertificate(new LogOnStatusAlert());

        DSSDocument doubleSignedDocument = super.sign();

        documentToSign = originalDocument;
        signingAlias = EXPIRED_USER;
        return doubleSignedDocument;
    }

    @Override
    protected CertificateVerifier getCompleteCertificateVerifier() {
        CertificateVerifier certificateVerifier = super.getCompleteCertificateVerifier();
        certificateVerifier.setRevocationFallback(true);
        return certificateVerifier;
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        assertEquals(2, diagnosticData.getSignatures().size());
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
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        int bLevelCounter = 0;
        int ltaLevelCounter = 0;
        for (SignatureWrapper signatureWrapper : diagnosticData.getSignatures()) {
            if (SignatureLevel.CAdES_BASELINE_B == signatureWrapper.getSignatureFormat()) {
                ++bLevelCounter;
            } else if (SignatureLevel.CAdES_BASELINE_LTA == signatureWrapper.getSignatureFormat()) {
                ++ltaLevelCounter;
            }
        }
        assertEquals(1, bLevelCounter);
        assertEquals(1, ltaLevelCounter);
    }

    @Override
    protected void checkExtractedContent(ASiCContent asicContent) {
        assertNotNull(asicContent.getMimeTypeDocument());
        assertEquals(1, asicContent.getSignedDocuments().size());
        assertEquals(1, asicContent.getRootLevelSignedDocuments().size());

        assertEquals(2, asicContent.getSignatureDocuments().size());
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        // skip
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected DocumentSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
        signatureParameters.bLevel().setSigningDate(signingTime);
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        return signatureParameters;
    }

    @Override
    protected String getSigningAlias() {
        return signingAlias;
    }

}
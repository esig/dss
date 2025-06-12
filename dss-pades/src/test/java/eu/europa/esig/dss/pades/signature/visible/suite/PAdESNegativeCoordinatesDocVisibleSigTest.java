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
package eu.europa.esig.dss.pades.signature.visible.suite;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ImageScaling;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentHorizontal;
import eu.europa.esig.dss.enumerations.VisualSignatureAlignmentVertical;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.AbstractPAdESTestSignature;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PAdESNegativeCoordinatesDocVisibleSigTest extends AbstractPAdESTestSignature {

    private final DSSDocument RED_CROSS_IMAGE = new InMemoryDocument(
            getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG);

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument originalDocument;

    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        originalDocument = new InMemoryDocument(getClass().getResourceAsStream("/visualSignature/coordinates/doc-negative-coordinates.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Test
    void test() {
        documentToSign = originalDocument;

        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(RED_CROSS_IMAGE);

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(20);
        fieldParameters.setOriginY(50);
        fieldParameters.setWidth(100);
        fieldParameters.setHeight(50);
        imageParameters.setFieldParameters(fieldParameters);
        imageParameters.setImageScaling(ImageScaling.STRETCH);

        signatureParameters.setImageParameters(imageParameters);

        final DSSDocument signedDocument = sign();
        verify(signedDocument);

        documentToSign = signedDocument;

        fieldParameters.setOriginX(80);
        fieldParameters.setOriginY(50);

        Exception exception = assertThrows(AlertException.class, super::sign);
        assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

        fieldParameters.setOriginX(150);
        fieldParameters.setOriginY(50);

        final DSSDocument doubleSignedDocument = sign();
        verify(doubleSignedDocument);
    }

    @Test
    void positionTest() {
        documentToSign = originalDocument;

        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(RED_CROSS_IMAGE);

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(20);
        fieldParameters.setOriginY(50);
        fieldParameters.setWidth(100);
        fieldParameters.setHeight(50);
        imageParameters.setFieldParameters(fieldParameters);
        imageParameters.setImageScaling(ImageScaling.STRETCH);

        imageParameters.setAlignmentHorizontal(VisualSignatureAlignmentHorizontal.RIGHT);
        imageParameters.setAlignmentVertical(VisualSignatureAlignmentVertical.BOTTOM);

        signatureParameters.setImageParameters(imageParameters);

        final DSSDocument signedDocument = sign();
        verify(signedDocument);

        documentToSign = signedDocument;

        fieldParameters.setOriginX(20);
        fieldParameters.setOriginY(80);

        Exception exception = assertThrows(AlertException.class, super::sign);
        assertEquals("The new signature field position overlaps with an existing annotation!", exception.getMessage());

        fieldParameters.setOriginX(20);
        fieldParameters.setOriginY(150);

        final DSSDocument doubleSignedDocument = sign();
        verify(doubleSignedDocument);
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkSignatureScopes(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    public void signAndVerify() {
        // do nothing
    }

    @Override
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
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
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}

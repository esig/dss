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
package eu.europa.esig.dss.pades.signature.visible.suite;

import eu.europa.esig.dss.enumerations.ImageScaling;
import eu.europa.esig.dss.enumerations.MimeTypeEnum;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TextWrapping;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.AbstractPAdESTestSignature;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.io.IOException;
import java.util.Date;

public class PAdESExistingSignatureFieldTest extends AbstractPAdESTestSignature {

    private final DSSDocument RED_CROSS_IMAGE = new InMemoryDocument(
            getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeTypeEnum.JPEG);

    private final DSSDocument PNG_IMAGE = new InMemoryDocument(
            getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeTypeEnum.PNG);

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/doc.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);
        signatureParameters.getImageParameters().getFieldParameters().setFieldId("Signature1");

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Test
    void simpleImageTest() throws Exception {
        SignatureImageParameters imageParameters = signatureParameters.getImageParameters();
        imageParameters.setImage(RED_CROSS_IMAGE);

        super.signAndVerify();
    }

    @Test
    void simpleImageCenterScalingTest() throws Exception {
        SignatureImageParameters imageParameters = signatureParameters.getImageParameters();
        imageParameters.setImage(RED_CROSS_IMAGE);
        imageParameters.setImageScaling(ImageScaling.CENTER);
        imageParameters.setBackgroundColor(Color.PINK);

        super.signAndVerify();
    }

    @Test
    void textOnlyTest() throws IOException {
        SignatureImageParameters imageParameters = signatureParameters.getImageParameters();
        SignatureImageTextParameters textParameters = imageParameters.getTextParameters();
        textParameters.setText("Signature 1");

        super.signAndVerify();
    }

    @Test
    void zoomAndRotationTest() throws IOException {
        SignatureImageParameters imageParameters = signatureParameters.getImageParameters();
        imageParameters.setImage(PNG_IMAGE);
        imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);
        imageParameters.setBackgroundColor(Color.PINK);
        imageParameters.getFieldParameters().setRotation(VisualSignatureRotation.ROTATE_90);

        super.signAndVerify();
    }

    @Test
    void autoFitTest() throws IOException {
        SignatureImageParameters imageParameters = signatureParameters.getImageParameters();

        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText("Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n" +
                "Date: 2021.01.01 01:01:01 WET\n" +
                "Reason: my-reason\n" +
                "Location: my-location");
        textParameters.setTextWrapping(TextWrapping.FILL_BOX);
        imageParameters.setTextParameters(textParameters);

        signatureParameters.setImageParameters(imageParameters);

        super.signAndVerify();
    }

    @Test
    void autoFitAndLinebreakTest() throws IOException {
        SignatureImageParameters imageParameters = signatureParameters.getImageParameters();

        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText("Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n" +
                "Date: 2021.01.01 01:01:01 WET\n" +
                "Reason: my-reason\n" +
                "Location: my-location");
        textParameters.setTextWrapping(TextWrapping.FILL_BOX_AND_LINEBREAK);
        imageParameters.setTextParameters(textParameters);

        signatureParameters.setImageParameters(imageParameters);

        super.signAndVerify();
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
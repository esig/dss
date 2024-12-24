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

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TextWrapping;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.AbstractPAdESTestSignature;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class PAdESTextWrappingTest extends AbstractPAdESTestSignature {

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    void init() throws Exception {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/sample.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Test
    void testOverflow() throws Exception {
        SignatureImageParameters imageParameters = new SignatureImageParameters();

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(50);
        fieldParameters.setWidth(100);
        fieldParameters.setHeight(100);
        imageParameters.setFieldParameters(fieldParameters);

        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText("Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n" +
                "Date: 2021.01.01 01:01:01 WET\n" +
                "Reason: my-reason\n" +
                "Location: my-location");
        textParameters.setTextWrapping(TextWrapping.FONT_BASED);
        imageParameters.setTextParameters(textParameters);

        signatureParameters.setImageParameters(imageParameters);

        super.signAndVerify();
    }

    @Test
    void testFillBox() throws Exception {
        SignatureImageParameters imageParameters = new SignatureImageParameters();

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(50);
        fieldParameters.setWidth(100);
        fieldParameters.setHeight(100);
        imageParameters.setFieldParameters(fieldParameters);

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
    void testFillBoxAndLinebreak() throws Exception {
        SignatureImageParameters imageParameters = new SignatureImageParameters();

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(50);
        fieldParameters.setWidth(100);
        fieldParameters.setHeight(100);
        imageParameters.setFieldParameters(fieldParameters);

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

    @Test
    void loremIpsumLinebreakTest() throws IOException {
        SignatureImageParameters imageParameters = new SignatureImageParameters();

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(50);
        fieldParameters.setWidth(200);
        fieldParameters.setHeight(100);
        imageParameters.setFieldParameters(fieldParameters);

        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec velit neque, " +
                "aliquet id mauris vitae, auctor porta velit. Mauris consectetur in quam ut ultrices. Maecenas " +
                "id facilisis urna. Pellentesque egestas, neque ac gravida tristique, nulla mi placerat nibh, " +
                "id sollicitudin dolor ex sed nulla. Fusce luctus finibus tortor, eu congue erat faucibus ultricies. " +
                "Duis at tincidunt velit, eget mattis nisl. Donec rhoncus elementum venenatis. Quisque faucibus " +
                "scelerisque pretium. Aliquam pharetra dignissim ex, vitae finibus tellus euismod eu. Praesent rhoncus, " +
                "ligula sed vehicula fermentum, arcu eros rutrum enim, non sollicitudin dui mi sit amet metus. " +
                "Aliquam mollis nunc sed arcu dapibus, quis scelerisque arcu viverra. Ut volutpat, quam vitae " +
                "vestibulum viverra, sem dui posuere neque, in egestas metus augue in enim. Ut suscipit risus ipsum, " +
                "eget cursus elit lobortis vulputate. Nunc suscipit dui ut magna vestibulum, sed consequat diam hendrerit. " +
                "Nullam mattis augue risus, eget ullamcorper odio ultricies ac.");
        textParameters.setTextWrapping(TextWrapping.FILL_BOX_AND_LINEBREAK);
        imageParameters.setTextParameters(textParameters);

        signatureParameters.setImageParameters(imageParameters);

        super.signAndVerify();
    }

    @Test
    void noSignatureFieldBoxTest() throws Exception {
        SignatureImageParameters imageParameters = new SignatureImageParameters();

        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText("Digitally signed by JOHN GEORGE ANTHONY WILLIAMS\n" +
                "Date: 2021.01.01 01:01:01 WET\n" +
                "Reason: my-reason\n" +
                "Location: my-location");
        textParameters.setTextWrapping(TextWrapping.FILL_BOX);
        imageParameters.setTextParameters(textParameters);

        signatureParameters.setImageParameters(imageParameters);

        Exception exception = assertThrows(IllegalArgumentException.class, () -> super.signAndVerify());
        assertEquals("Signature field dimensions are not defined! Unable to use 'FILL_BOX' option.", exception.getMessage());

        textParameters.setTextWrapping(TextWrapping.FILL_BOX_AND_LINEBREAK);
        exception = assertThrows(IllegalArgumentException.class, () -> super.signAndVerify());
        assertEquals("Signature field dimensions are not defined! Unable to use 'FILL_BOX_AND_LINEBREAK' option.", exception.getMessage());
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

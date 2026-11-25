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
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.AbstractPAdESTestSignature;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PAdESWithFontSubsetWithAtomicMethodsTest extends AbstractPAdESTestSignature {

    private static final String FONT_NAME = "PTSerif-Regular";

    private DSSFileFont font;

    private PAdESService service;
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

        font = DSSFileFont.initializeDefault(); // PTSerif-Regular by default

        SignatureImageParameters signatureImageParameters = new SignatureImageParameters();
        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText("My signature");
        textParameters.setFont(font);
        signatureImageParameters.setTextParameters(textParameters);
        signatureParameters.setImageParameters(signatureImageParameters);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Test
    void embedFontTest() throws IOException {
        font.setEmbedFontSubset(false);

        DSSDocument signedDocument = sign();
        // signedDocument.save("target/embed_font_test.pdf");/PAdESWithFontSubsetWithAtomicMethodsTest.java
        assertContainsSubset(signedDocument, false);
        verify(signedDocument);
    }

    @Test
    void embedSubsetTest() throws IOException {
        font.setEmbedFontSubset(true);

        DSSDocument signedDocument = sign();
        // signedDocument.save("target/embed_subset_test.pdf");
        assertContainsSubset(signedDocument, true);
        verify(signedDocument);
    }

    private void assertContainsSubset(DSSDocument document, boolean embedSubset) throws IOException {
        try (InputStream docIs = document.openStream(); InputStream fontIs = font.getInputStream()) {
            assertNotEquals(Utils.getInputStreamSize(docIs) > Utils.getInputStreamSize(fontIs), embedSubset);
        }
        byte[] docBytes = DSSUtils.toByteArray(document);
        String pdfString = new String(docBytes);
        assertNotEquals(pdfString.contains("/" + FONT_NAME), embedSubset);
        assertEquals(pdfString.contains("+" + FONT_NAME), embedSubset);
    }

    @Override
    protected DSSDocument sign() {
        PAdESService service = getService();

        DSSDocument toBeSigned = getDocumentToSign();
        PAdESSignatureParameters params = getSignatureParameters();

        ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);
        SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(), getPrivateKeyEntry());
        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));

        toBeSigned = createDocumentCopy(toBeSigned);
        params = createSignatureParametersCopy(params);

        return service.signDocument(toBeSigned, params, signatureValue);
    }

    private DSSDocument createDocumentCopy(DSSDocument document) {
        return new InMemoryDocument(DSSUtils.toByteArray(document), document.getName(), document.getMimeType());
    }

    private PAdESSignatureParameters createSignatureParametersCopy(PAdESSignatureParameters signatureParameters) {
        PAdESSignatureParameters signatureParametersCopy = new PAdESSignatureParameters();
        signatureParametersCopy.setSigningCertificate(signatureParameters.getSigningCertificate());
        signatureParametersCopy.setCertificateChain(signatureParameters.getCertificateChain());
        signatureParametersCopy.setSignatureLevel(signatureParameters.getSignatureLevel());
        signatureParametersCopy.setSignaturePackaging(signatureParameters.getSignaturePackaging());
        signatureParametersCopy.bLevel().setSigningDate(signatureParameters.bLevel().getSigningDate());
        signatureParametersCopy.setImageParameters(signatureParameters.getImageParameters());
        return signatureParametersCopy;
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
    protected PAdESService getService() {
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

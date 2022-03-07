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
package eu.europa.esig.dss.pades.signature.visible.nativedrawer;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.pades.DSSFileFont;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.SignatureImageTextParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.AbstractPAdESTestSignature;
import eu.europa.esig.dss.pdf.PDFServiceMode;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxNativeObjectFactory;
import eu.europa.esig.dss.pdf.pdfbox.PdfBoxSignatureService;
import eu.europa.esig.dss.pdf.pdfbox.visible.PdfBoxSignatureDrawer;
import eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer.NativePdfBoxVisibleSignatureDrawer;
import eu.europa.esig.dss.pdf.pdfbox.visible.nativedrawer.PdfBoxNativeSignatureDrawerFactory;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class PdfBoxNativeDrawerFontSubsetTest extends AbstractPAdESTestSignature {

    private static final String FONT_NAME = "PTSerif-Regular";

    private DSSFileFont font;
    private boolean embedSubset;

    private PAdESService service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
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
        signatureImageParameters.setTextParameters(textParameters);
        signatureParameters.setImageParameters(signatureImageParameters);

        service = new PAdESService(getOfflineCertificateVerifier());
        service.setPdfObjFactory(new MockPdfBoxNativeObjectFactory());
    }

    @Test
    public void embedFontTest() throws IOException {
        embedSubset = false;

        DSSDocument signedDocument = sign();
        // signedDocument.save("target/test.pdf");
        assertContainsSubset(signedDocument, false);
        verify(signedDocument);
    }

    @Test
    public void embedSubsetTest() throws IOException {
        embedSubset = true;

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

    private class MockPdfBoxNativeObjectFactory extends PdfBoxNativeObjectFactory {

        @Override
        public PDFSignatureService newPAdESSignatureService() {
            return new PdfBoxSignatureService(PDFServiceMode.SIGNATURE, new MockPdfBoxNativeSignatureDrawerFactory());
        }

        @Override
        public PDFSignatureService newContentTimestampService() {
            return new PdfBoxSignatureService(PDFServiceMode.CONTENT_TIMESTAMP, new MockPdfBoxNativeSignatureDrawerFactory());
        }

        @Override
        public PDFSignatureService newSignatureTimestampService() {
            return new PdfBoxSignatureService(PDFServiceMode.SIGNATURE_TIMESTAMP, new MockPdfBoxNativeSignatureDrawerFactory());
        }

        @Override
        public PDFSignatureService newArchiveTimestampService() {
            return new PdfBoxSignatureService(PDFServiceMode.ARCHIVE_TIMESTAMP, new MockPdfBoxNativeSignatureDrawerFactory());
        }

    }

    private class MockPdfBoxNativeSignatureDrawerFactory extends PdfBoxNativeSignatureDrawerFactory {

        @Override
        public PdfBoxSignatureDrawer getSignatureDrawer(SignatureImageParameters imageParameters) {
            NativePdfBoxVisibleSignatureDrawer nativePdfBoxVisibleSignatureDrawer = new NativePdfBoxVisibleSignatureDrawer();
            nativePdfBoxVisibleSignatureDrawer.setEmbedFontSubset(embedSubset);
            return nativePdfBoxVisibleSignatureDrawer;
        }

    }

}

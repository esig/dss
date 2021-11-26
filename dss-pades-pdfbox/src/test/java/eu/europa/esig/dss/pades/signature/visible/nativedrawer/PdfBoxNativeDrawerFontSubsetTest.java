package eu.europa.esig.dss.pades.signature.visible.nativedrawer;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
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
import eu.europa.esig.dss.pdfa.validation.PDFADocumentValidator;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PdfBoxNativeDrawerFontSubsetTest extends AbstractPAdESTestSignature {

    private static final String FONT_NAME = "PTSerif-Regular";

    private boolean embedSubset;

    private PAdESService service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(getClass().getResourceAsStream("/not_signed_pdfa.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

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
        assertContainsSubset(signedDocument, false);
        verify(signedDocument);
    }

    @Test
    public void embedSubsetTest() throws IOException {
        embedSubset = true;

        DSSDocument signedDocument = sign();
        assertContainsSubset(signedDocument, true);
        verify(signedDocument);
    }

    private void assertContainsSubset(DSSDocument document, boolean embedSubset) {
        byte[] docBytes = DSSUtils.toByteArray(document);
        String pdfString = new String(docBytes);
        assertNotEquals(pdfString.contains("/" + FONT_NAME), embedSubset);
        assertEquals(pdfString.contains("+" + FONT_NAME), embedSubset);
    }

    @Override
    protected SignedDocumentValidator getValidator(DSSDocument signedDocument) {
        PDFADocumentValidator validator = new PDFADocumentValidator(signedDocument);
        validator.setCertificateVerifier(getOfflineCertificateVerifier());
        return validator;
    }

    @Override
    protected void checkPDFAInfo(DiagnosticData diagnosticData) {
        super.checkPDFAInfo(diagnosticData);

        assertEquals(1, diagnosticData.getSignatures().size());

        assertTrue(diagnosticData.isPDFAValidationPerformed());
        assertEquals("PDF/A-1B", diagnosticData.getPDFAProfileId());
        assertTrue(diagnosticData.isPDFACompliant());
        assertTrue(Utils.isCollectionEmpty(diagnosticData.getPDFAValidationErrors()));
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

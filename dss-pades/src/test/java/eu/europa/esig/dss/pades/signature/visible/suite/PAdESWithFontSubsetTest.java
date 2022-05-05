package eu.europa.esig.dss.pades.signature.visible.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
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

public class PAdESWithFontSubsetTest extends AbstractPAdESTestSignature {

    private static final String FONT_NAME = "PTSerif-Regular";

    private DSSFileFont font;

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
        textParameters.setFont(font);
        signatureImageParameters.setTextParameters(textParameters);
        signatureParameters.setImageParameters(signatureImageParameters);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Test
    public void embedFontTest() throws IOException {
        font.setEmbedFontSubset(false);

        DSSDocument signedDocument = sign();
        // signedDocument.save("target/embed_font_test.pdf");
        assertContainsSubset(signedDocument, false);
        verify(signedDocument);
    }

    @Test
    public void embedSubsetTest() throws IOException {
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

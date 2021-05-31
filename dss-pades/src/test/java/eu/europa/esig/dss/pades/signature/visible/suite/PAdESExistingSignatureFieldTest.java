package eu.europa.esig.dss.pades.signature.visible.suite;

import eu.europa.esig.dss.enumerations.ImageScaling;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
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
            getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG);

    private final DSSDocument PNG_IMAGE = new InMemoryDocument(
            getClass().getResourceAsStream("/signature-image.png"), "signature-image.png", MimeType.PNG);

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
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
    public void simpleImageTest() throws Exception {
        SignatureImageParameters imageParameters = signatureParameters.getImageParameters();
        imageParameters.setImage(RED_CROSS_IMAGE);

        super.signAndVerify();
    }

    @Test
    public void simpleImageCenterScalingTest() throws Exception {
        SignatureImageParameters imageParameters = signatureParameters.getImageParameters();
        imageParameters.setImage(RED_CROSS_IMAGE);
        imageParameters.setImageScaling(ImageScaling.CENTER);
        imageParameters.setBackgroundColor(Color.PINK);

        super.signAndVerify();
    }

    @Test
    public void textOnlyTest() throws IOException {
        SignatureImageParameters imageParameters = signatureParameters.getImageParameters();
        SignatureImageTextParameters textParameters = imageParameters.getTextParameters();
        textParameters.setText("Signature 1");

        super.signAndVerify();
    }

    @Test
    public void zoomAndRotationTest() throws IOException {
        SignatureImageParameters imageParameters = signatureParameters.getImageParameters();
        imageParameters.setImage(PNG_IMAGE);
        imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);
        imageParameters.setBackgroundColor(Color.PINK);
        imageParameters.setRotation(VisualSignatureRotation.ROTATE_90);

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
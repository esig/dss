package eu.europa.esig.dss.pades.signature.visible.suite;

import eu.europa.esig.dss.enumerations.ImageScaling;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.PAdESTimestampParameters;
import eu.europa.esig.dss.pades.SignatureFieldParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.pades.signature.suite.AbstractPAdESTestSignature;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.awt.Color;
import java.util.Date;

public class PAdESVisibleImageScalingTest extends AbstractPAdESTestSignature {

    private final DSSDocument RED_CROSS_IMAGE = new InMemoryDocument(
            getClass().getResourceAsStream("/small-red.jpg"), "small-red.jpg", MimeType.JPEG);

    private DocumentSignatureService<PAdESSignatureParameters, PAdESTimestampParameters> service;
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

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Test
    public void stretchImageTest() throws Exception {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(RED_CROSS_IMAGE);

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(20);
        fieldParameters.setOriginY(50);
        fieldParameters.setWidth(100);
        fieldParameters.setHeight(300);
        imageParameters.setFieldParameters(fieldParameters);
        imageParameters.setImageScaling(ImageScaling.STRETCH);

        signatureParameters.setImageParameters(imageParameters);

        super.signAndVerify();
    }

    @Test
    public void zoomAndCenterImageTest() throws Exception {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(RED_CROSS_IMAGE);

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(20);
        fieldParameters.setOriginY(50);
        fieldParameters.setWidth(100);
        fieldParameters.setHeight(300);
        imageParameters.setFieldParameters(fieldParameters);
        imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);
        imageParameters.setBackgroundColor(Color.PINK);

        signatureParameters.setImageParameters(imageParameters);

        super.signAndVerify();
    }

    @Test
    public void zoomAndCenterImageChangeDimensionsTest() throws Exception {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(RED_CROSS_IMAGE);

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(20);
        fieldParameters.setOriginY(50);
        fieldParameters.setWidth(300);
        fieldParameters.setHeight(100);
        imageParameters.setFieldParameters(fieldParameters);
        imageParameters.setImageScaling(ImageScaling.ZOOM_AND_CENTER);
        imageParameters.setBackgroundColor(Color.PINK);

        signatureParameters.setImageParameters(imageParameters);

        super.signAndVerify();
    }

    @Test
    public void centerImageTest() throws Exception {
        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setImage(RED_CROSS_IMAGE);

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(20);
        fieldParameters.setOriginY(50);
        fieldParameters.setWidth(100);
        fieldParameters.setHeight(300);
        imageParameters.setFieldParameters(fieldParameters);
        imageParameters.setImageScaling(ImageScaling.CENTER);
        imageParameters.setBackgroundColor(Color.YELLOW);

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

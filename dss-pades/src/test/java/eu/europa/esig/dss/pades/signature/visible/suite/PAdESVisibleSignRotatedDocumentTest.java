package eu.europa.esig.dss.pades.signature.visible.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.VisualSignatureRotation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
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
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.awt.Color;
import java.io.File;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Stream;

/**
 * For manual testing
 *
 */
@Tag("slow")
public class PAdESVisibleSignRotatedDocumentTest extends AbstractPAdESTestSignature {

    protected PAdESService service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    private static Stream<Arguments> data() throws URISyntaxException {
        List<File> signable = new ArrayList<>();
        signable.add(new File(PAdESVisibleSignRotatedDocumentTest.class.getResource("/visualSignature/test.pdf").toURI()));
        signable.add(new File(PAdESVisibleSignRotatedDocumentTest.class.getResource("/visualSignature/test_90.pdf").toURI()));
        signable.add(new File(PAdESVisibleSignRotatedDocumentTest.class.getResource("/visualSignature/test_180.pdf").toURI()));
        signable.add(new File(PAdESVisibleSignRotatedDocumentTest.class.getResource("/visualSignature/test_270.pdf").toURI()));
        signable.add(new File(PAdESVisibleSignRotatedDocumentTest.class.getResource("/visualSignature/test_-90.pdf").toURI()));
        signable.add(new File(PAdESVisibleSignRotatedDocumentTest.class.getResource("/visualSignature/test_-180.pdf").toURI()));
        signable.add(new File(PAdESVisibleSignRotatedDocumentTest.class.getResource("/visualSignature/test_-270.pdf").toURI()));

        Collection<Arguments> dataToRun = new ArrayList<>();
        for (File document : signable) {
            for (VisualSignatureRotation rotation : VisualSignatureRotation.values()) {
                dataToRun.add(Arguments.of(document, rotation));
            }
        }
        return dataToRun.stream();
    }

    @ParameterizedTest(name = "Text visual signature for document and rotation {index} : {0} : {1}")
    @MethodSource("data")
    public void textTest(File file, VisualSignatureRotation rotation) {
        this.documentToSign = new FileDocument(file);
        this.documentToSign.setName("text_" + file.getName() + "_" + rotation.name() + ".pdf");

        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setRotation(rotation);

        SignatureImageTextParameters textParameters = new SignatureImageTextParameters();
        textParameters.setText("My signature");
        textParameters.setBackgroundColor(Color.PINK);
        imageParameters.setTextParameters(textParameters);

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(50);
        fieldParameters.setHeight(50);
        fieldParameters.setWidth(100);
        imageParameters.setFieldParameters(fieldParameters);

        signatureParameters.setImageParameters(imageParameters);

        super.signAndVerify();
    }

    @ParameterizedTest(name = "Image visual signature for document and rotation {index} : {0} : {1}")
    @MethodSource("data")
    public void imageTest(File file, VisualSignatureRotation rotation) {
        this.documentToSign = new FileDocument(file);
        this.documentToSign.setName("image_" + file.getName() + "_" + rotation.name() + ".pdf");

        SignatureImageParameters imageParameters = new SignatureImageParameters();
        imageParameters.setBackgroundColor(Color.PINK);
        imageParameters.setRotation(rotation);
        imageParameters.setImage(new InMemoryDocument(PAdESVisibleSignRotatedDocumentTest.class.getResourceAsStream("/signature-image.png")));

        SignatureFieldParameters fieldParameters = new SignatureFieldParameters();
        fieldParameters.setOriginX(100);
        fieldParameters.setOriginY(50);
        fieldParameters.setHeight(50);
        fieldParameters.setWidth(100);
        imageParameters.setFieldParameters(fieldParameters);

        signatureParameters.setImageParameters(imageParameters);


        super.signAndVerify();
    }

    @Override
    public void signAndVerify() {
        // do nothing
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
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}

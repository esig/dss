package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.SimpleASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeEach;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCECAdESLevelBWithSignatureNameTest extends AbstractASiCECAdESTestSignature {

    private static final String SIGNATURE_FILENAME = "signature-toto.p7s";
    private ASiCWithCAdESService service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT);

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        service = new ASiCWithCAdESService(getOfflineCertificateVerifier());
        SimpleASiCWithCAdESFilenameFactory asicFilenameFactory = new SimpleASiCWithCAdESFilenameFactory();
        asicFilenameFactory.setSignatureFilename(SIGNATURE_FILENAME);
        asicFilenameFactory.setManifestFilename("ASiCManifest.xml");
        service.setAsicFilenameFactory(asicFilenameFactory);
    }

    @Override
    protected void checkExtractedContent(ASiCContent asicContent) {
        assertEquals(0, asicContent.getUnsupportedDocuments().size());

        List<DSSDocument> signatureDocuments = asicContent.getSignatureDocuments();
        assertEquals(1, signatureDocuments.size());
        assertEquals("META-INF/" + SIGNATURE_FILENAME, signatureDocuments.get(0).getName());

        List<DSSDocument> manifestDocuments = asicContent.getManifestDocuments();
        assertEquals(1, manifestDocuments.size());
        assertEquals("META-INF/ASiCManifest.xml", manifestDocuments.get(0).getName());

        List<DSSDocument> signedDocuments = asicContent.getSignedDocuments();
        assertEquals(1, signedDocuments.size());
        assertEquals("test.text", signedDocuments.get(0).getName());

        DSSDocument mimeTypeDocument = asicContent.getMimeTypeDocument();

        byte[] mimeTypeContent = DSSUtils.toByteArray(mimeTypeDocument);
        assertEquals(MimeType.ASICE.getMimeTypeString(), new String(mimeTypeContent, StandardCharsets.UTF_8));

        assertTrue(Utils.isStringEmpty(asicContent.getZipComment()));

    }

    @Override
    protected ASiCWithCAdESService getService() {
        return service;
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
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

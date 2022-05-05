package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.SimpleASiCWithCAdESFilenameFactory;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.common.ASiCContent;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.BeforeEach;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCECAdESLevelBCustomManifestNameTest extends AbstractASiCEWithCAdESMultipleDocumentsTestSignature {

    private ASiCWithCAdESService service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private List<DSSDocument> documentsToSign = new ArrayList<>();

    @BeforeEach
    public void init() throws Exception {
        documentsToSign.add(new InMemoryDocument("Hello World !".getBytes(), "test.text", MimeType.TEXT));
        documentsToSign.add(new InMemoryDocument("Bye World !".getBytes(), "test2.text", MimeType.TEXT));
        documentsToSign.add(new InMemoryDocument(DSSUtils.EMPTY_BYTE_ARRAY, "emptyByteArray"));

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_B);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        service = new ASiCWithCAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        SimpleASiCWithCAdESFilenameFactory filenameFactory = new SimpleASiCWithCAdESFilenameFactory();
        filenameFactory.setManifestFilename("manifest.xml");
        getService().setAsicFilenameFactory(filenameFactory);

        Exception exception = assertThrows(IllegalArgumentException.class, () -> super.sign());
        assertEquals("A manifest file within ASiC with CAdES container shall match the template " +
                        "'META-INF/ASiCManifest*.xml'!", exception.getMessage());

        filenameFactory.setManifestFilename("ASiCManifest.xml");
        getService().setAsicFilenameFactory(filenameFactory);

        return super.sign();
    }

    @Override
    protected void checkExtractedContent(ASiCContent asicContent) {
        super.checkExtractedContent(asicContent);

        assertEquals(1, asicContent.getManifestDocuments().size());
        assertEquals("META-INF/ASiCManifest.xml", asicContent.getManifestDocuments().get(0).getName());
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        List<DSSDocument> retrievedDocuments = validator.getOriginalDocuments(diagnosticData.getFirstSignatureId());
        for (DSSDocument document : documentsToSign) {
            boolean found = false;
            for (DSSDocument retrievedDoc : retrievedDocuments) {
                if (Arrays.equals(DSSUtils.toByteArray(document), DSSUtils.toByteArray(retrievedDoc))) {
                    found = true;
                }
            }
            assertTrue(found);
        }
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return documentsToSign;
    }

    @Override
    protected ASiCWithCAdESService getService() {
        return service;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}

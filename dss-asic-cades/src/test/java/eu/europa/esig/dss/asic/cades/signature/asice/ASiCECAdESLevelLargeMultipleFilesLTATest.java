package eu.europa.esig.dss.asic.cades.signature.asice;

import eu.europa.esig.dss.asic.cades.ASiCWithCAdESSignatureParameters;
import eu.europa.esig.dss.asic.cades.ASiCWithCAdESTimestampParameters;
import eu.europa.esig.dss.asic.cades.signature.ASiCWithCAdESService;
import eu.europa.esig.dss.asic.common.SecureContainerHandlerBuilder;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.MultipleDocumentsSignatureService;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
class ASiCECAdESLevelLargeMultipleFilesLTATest extends AbstractASiCEWithCAdESMultipleDocumentsTestSignature {

    private ASiCWithCAdESService service;
    private ASiCWithCAdESSignatureParameters signatureParameters;
    private List<FileDocument> documentToSigns;

    private TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder;

    @BeforeEach
    void init() throws Exception {
        tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();
        tempFileResourcesHandlerBuilder.setTempFileDirectory(new File("target"));

        SecureContainerHandlerBuilder secureContainerHandlerBuilder = new SecureContainerHandlerBuilder()
                .setResourcesHandlerBuilder(tempFileResourcesHandlerBuilder);
        ZipUtils.getInstance().setZipContainerHandlerBuilder(secureContainerHandlerBuilder);

        documentToSigns = new ArrayList<>();
        documentToSigns.add(generateLargeFile(1));
        documentToSigns.add(generateLargeFile(2));
        documentToSigns.add(generateLargeFile(3));

        signatureParameters = new ASiCWithCAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.CAdES_BASELINE_LTA);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_E);

        // precompute
        documentToSigns.parallelStream().forEach(d -> d.getDigestValue(signatureParameters.getDigestAlgorithm()));

        service = new ASiCWithCAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @AfterEach
    void clean() {
        for (FileDocument fileDocument : documentToSigns) {
            File file = fileDocument.getFile();
            assertTrue(file.exists());
            assertTrue(file.delete());
            assertFalse(file.exists());
        }

        tempFileResourcesHandlerBuilder.clear();
    }

    private FileDocument generateLargeFile(int count) throws IOException {
        File file = new File("target/large-binary-" + count + ".bin");

        long size = 0x00FFFFFF; // Integer.MAX_VALUE -1
        byte [] data = new byte[(int)size];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(data);

        try (FileOutputStream fos = new FileOutputStream(file)) {
            for (int i = 0; i < 100; i++) {
                fos.write(data);
            }
        }

        return new FileDocument(file);
    }

    @Test
    @Override
    public void signAndVerify() {
        final DSSDocument signedDocument = sign();

        assertNotNull(signedDocument.getName());
        assertNotNull(signedDocument.getMimeType());

        checkMimeType(signedDocument);

        verify(signedDocument);
    }

    @Override
    protected void verifyOriginalDocuments(SignedDocumentValidator validator, DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected List<DSSDocument> getDocumentsToSign() {
        return new ArrayList<>(documentToSigns);
    }

    @Override
    protected MultipleDocumentsSignatureService<ASiCWithCAdESSignatureParameters, ASiCWithCAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected ASiCWithCAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }


    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}
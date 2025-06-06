package eu.europa.esig.dss.asic.xades.signature.asics;

import eu.europa.esig.dss.asic.common.SecureContainerHandlerBuilder;
import eu.europa.esig.dss.asic.common.ZipUtils;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.signature.DocumentSignatureService;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.xades.XAdESTimestampParameters;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("slow")
class ASiCSXAdESLevelLargeFileLTATest extends AbstractASiCSXAdESTestSignature {

    private DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> service;
    private ASiCWithXAdESSignatureParameters signatureParameters;
    private FileDocument documentToSign;

    private TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder;

    @BeforeEach
    void init() throws Exception {
        tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();
        tempFileResourcesHandlerBuilder.setTempFileDirectory(new File("target"));

        SecureContainerHandlerBuilder secureContainerHandlerBuilder = new SecureContainerHandlerBuilder()
                .setResourcesHandlerBuilder(tempFileResourcesHandlerBuilder);
        ZipUtils.getInstance().setZipContainerHandlerBuilder(secureContainerHandlerBuilder);

        documentToSign = generateLargeFile();

        signatureParameters = new ASiCWithXAdESSignatureParameters();
        signatureParameters.bLevel().setSigningDate(new Date());
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_LTA);
        signatureParameters.aSiC().setContainerType(ASiCContainerType.ASiC_S);

        service = new ASiCWithXAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getGoodTsa());
    }

    @AfterEach
    void clean() {
        File file = documentToSign.getFile();
        assertTrue(file.exists());
        assertTrue(file.delete());
        assertFalse(file.exists());

        tempFileResourcesHandlerBuilder.clear();
    }

    private FileDocument generateLargeFile() throws IOException {
        File file = new File("target/large-binary.bin");

        long size = 0x00FFFFFF; // Integer.MAX_VALUE -1
        byte [] data = new byte[(int)size];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(data);

        try (FileOutputStream fos = new FileOutputStream(file)) {
            for (int i = 0; i < 500; i++) {
                fos.write(data);
            }
        }

        return new FileDocument(file);
    }

    @Override
    @Test
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
    protected DocumentSignatureService<ASiCWithXAdESSignatureParameters, XAdESTimestampParameters> getService() {
        return service;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getSignatureParameters() {
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

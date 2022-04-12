package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.MimeType;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.resources.TempFileResourcesHandlerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This unit test evaluates the memory consumption when using a {@code TempFileResourcesFactory} implementation.
 *
 */
public class PAdESLevelBSignWithFileResourcesTest extends AbstractPAdESTestSignature {

    private static final Logger LOG = LoggerFactory.getLogger(PAdESLevelBSignWithFileResourcesTest.class);

    private PAdESService service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(PAdESLevelBSignWithFileResourcesTest.class
                .getResourceAsStream("/big_file.pdf"), "big_file.pdf", MimeType.PDF);

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        service = new PAdESService(getCompleteCertificateVerifier());
        service.setTspSource(getAlternateGoodTsa());
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument toBeSigned = getDocumentToSign();
        PAdESSignatureParameters params = getSignatureParameters();
        PAdESService service = getService();

        TempFileResourcesHandlerBuilder tempFileResourcesHandlerBuilder = new TempFileResourcesHandlerBuilder();
        service.setResourcesHandlerBuilder(tempFileResourcesHandlerBuilder);

        Runtime.getRuntime().gc();
        double memoryBefore = getRuntimeMemoryInMegabytes();

        ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);

        double memoryAfterGetDataToSign = getRuntimeMemoryInMegabytes();
        LOG.info("Memory used for getDataToSign() : {}Mb", memoryAfterGetDataToSign - memoryBefore);

        SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(),
                getSignatureParameters().getMaskGenerationFunction(), getPrivateKeyEntry());
        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));

        Runtime.getRuntime().gc();
        memoryBefore = getRuntimeMemoryInMegabytes();

        DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

        double memoryAfterSignDocument = getRuntimeMemoryInMegabytes();
        LOG.info("Memory used for signDocument() : {}Mb", memoryAfterSignDocument - memoryBefore);
        assertTrue(signedDocument instanceof FileDocument);

        params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_T);

        Runtime.getRuntime().gc();
        memoryBefore = getRuntimeMemoryInMegabytes();

        DSSDocument tLevelSignature = service.extendDocument(signedDocument, params);

        double memoryTLevelExtendDocument = getRuntimeMemoryInMegabytes();
        LOG.info("Memory used for T-Level extendDocument() : {}Mb", memoryTLevelExtendDocument - memoryBefore);
        assertTrue(tLevelSignature instanceof FileDocument);

        params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);

        Runtime.getRuntime().gc();
        memoryBefore = getRuntimeMemoryInMegabytes();

        DSSDocument ltLevelSignature = service.extendDocument(tLevelSignature, params);

        double memoryLTLevelExtendDocument = getRuntimeMemoryInMegabytes();
        LOG.info("Memory used for LT-Level extendDocument() : {}Mb", memoryLTLevelExtendDocument - memoryBefore);
        assertTrue(ltLevelSignature instanceof FileDocument);

        params.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LTA);

        Runtime.getRuntime().gc();
        memoryBefore = getRuntimeMemoryInMegabytes();

        DSSDocument ltaLevelSignature = service.extendDocument(ltLevelSignature, params);

        double memoryLTALevelExtendDocument = getRuntimeMemoryInMegabytes();
        LOG.info("Memory used for LTA-Level extendDocument() : {}Mb", memoryLTALevelExtendDocument - memoryBefore);
        assertTrue(ltaLevelSignature instanceof FileDocument);

        return ltaLevelSignature;
    }

    private static double getRuntimeMemoryInMegabytes() {
        // Get the Java runtime
        Runtime runtime = Runtime.getRuntime();
        // Calculate the used memory
        double memory = runtime.totalMemory() - runtime.freeMemory();
        return bytesToMegabytes(memory);
    }

    private static double bytesToMegabytes(double bytes) {
        return bytes / (1024L * 1024L);
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
    protected DSSDocument getDocumentToSign() {
        return documentToSign;
    }

    @Override
    protected String getSigningAlias() {
        return GOOD_USER;
    }

}

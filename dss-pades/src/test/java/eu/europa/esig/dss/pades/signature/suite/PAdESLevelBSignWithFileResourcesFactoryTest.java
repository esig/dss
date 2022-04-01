package eu.europa.esig.dss.pades.signature.suite;

import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.signature.resources.ResourcesFactoryProvider;
import eu.europa.esig.dss.signature.resources.TempFileResourcesFactoryBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This unit test evaluates the memory consumption when using a {@code TempFileResourcesFactory} implementation.
 *
 * Note : use -XX:+UnlockExperimentalVMOptions -XX:+UseEpsilonGC
 *        arguments to disable garbage collector for manual testing
 */
public class PAdESLevelBSignWithFileResourcesFactoryTest extends AbstractPAdESTestSignature {

    private static final Logger LOG = LoggerFactory.getLogger(PAdESLevelBSignWithFileResourcesFactoryTest.class);

    private PAdESService service;
    private PAdESSignatureParameters signatureParameters;
    private DSSDocument documentToSign;

    @BeforeEach
    public void init() throws Exception {
        documentToSign = new InMemoryDocument(PAdESLevelBSignWithFileResourcesFactoryTest.class.getResourceAsStream("/big_file.pdf"));

        signatureParameters = new PAdESSignatureParameters();
        signatureParameters.setSigningCertificate(getSigningCert());
        signatureParameters.setCertificateChain(getCertificateChain());
        signatureParameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_B);

        service = new PAdESService(getOfflineCertificateVerifier());
    }

    @Override
    protected DSSDocument sign() {
        DSSDocument toBeSigned = getDocumentToSign();
        PAdESSignatureParameters params = getSignatureParameters();
        PAdESService service = getService();

        TempFileResourcesFactoryBuilder resourcesFactoryBuilder = new TempFileResourcesFactoryBuilder()
                .setTempFileDirectory(new File("target"));

        ResourcesFactoryProvider.getInstance().setResourcesFactoryBuilder(resourcesFactoryBuilder);

        double memoryBefore = getRuntimeMemoryInMegabytes();

        ToBeSigned dataToSign = service.getDataToSign(toBeSigned, params);

        double memoryAfterGetDataToSign = getRuntimeMemoryInMegabytes();
        LOG.info("Memory used for getDataToSign() : {}Mb", memoryAfterGetDataToSign - memoryBefore);

        SignatureValue signatureValue = getToken().sign(dataToSign, getSignatureParameters().getDigestAlgorithm(),
                getSignatureParameters().getMaskGenerationFunction(), getPrivateKeyEntry());
        assertTrue(service.isValidSignatureValue(dataToSign, signatureValue, getSigningCert()));

        memoryBefore = getRuntimeMemoryInMegabytes();

        DSSDocument signedDocument = service.signDocument(toBeSigned, params, signatureValue);

        double memoryAfterSignDocument = getRuntimeMemoryInMegabytes();
        LOG.info("Memory used for signDocument() : {}Mb", memoryAfterSignDocument - memoryBefore);

        assertTrue(signedDocument instanceof FileDocument);

        return signedDocument;
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

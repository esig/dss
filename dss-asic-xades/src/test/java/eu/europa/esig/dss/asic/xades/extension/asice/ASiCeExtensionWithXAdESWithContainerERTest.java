package eu.europa.esig.dss.asic.xades.extension.asice;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters;
import eu.europa.esig.dss.asic.xades.extension.AbstractASiCWithXAdESTestExtension;
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCeExtensionWithXAdESWithContainerERTest extends AbstractASiCWithXAdESTestExtension {

    private SignatureLevel finalSignatureLevel;

    private CertificateVerifier certificateVerifier;

    private Date extensionTime;

    @BeforeEach
    void init() {
        certificateVerifier = getOfflineCertificateVerifier();
        certificateVerifier.setAlertOnExpiredCertificate(new SilentOnStatusAlert());
        certificateVerifier.setAlertOnMissingRevocationData(new SilentOnStatusAlert());

        extensionTime = DSSUtils.parseRFCDate("2025-01-01T00:00:00Z");
    }

    @Test
    void bLevelWithERExtensionTest() {
        DSSDocument signedDocument = new FileDocument(new File("src/test/resources/validation/evidencerecord/xades-lt-with-er.sce"));

        certificateVerifier.setAugmentationAlertOnHigherSignatureLevel(new ExceptionOnStatusAlert());

        finalSignatureLevel = SignatureLevel.XAdES_BASELINE_T;
        Exception exception = assertThrows(IllegalInputException.class, () -> extendSignature(signedDocument));
        assertEquals("The modification of the signature is not possible! Reason : " +
                "a signature with a filename 'META-INF/signatures001.xml' is covered by another manifest.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.XAdES_BASELINE_LT;
        exception = assertThrows(IllegalInputException.class, () -> extendSignature(signedDocument));
        assertEquals("The modification of the signature is not possible! Reason : " +
                "a signature with a filename 'META-INF/signatures001.xml' is covered by another manifest.", exception.getMessage());

        finalSignatureLevel = SignatureLevel.XAdES_BASELINE_LTA;
        exception = assertThrows(IllegalInputException.class, () -> extendSignature(signedDocument));
        assertEquals("The modification of the signature is not possible! Reason : " +
                "a signature with a filename 'META-INF/signatures001.xml' is covered by another manifest.", exception.getMessage());
    }

    protected CertificateVerifier getCertificateVerifier() {
        return certificateVerifier;
    }

    @Override
    protected ASiCWithXAdESSignatureParameters getExtensionParameters() {
        ASiCWithXAdESSignatureParameters parameters = super.getExtensionParameters();
        parameters.bLevel().setSigningDate(extensionTime);
        return parameters;
    }

    @Override
    protected ASiCContainerType getContainerType() {
        return ASiCContainerType.ASiC_E;
    }

    @Override
    protected ASiCWithXAdESService getSignatureServiceToExtend() {
        ASiCWithXAdESService service = new ASiCWithXAdESService(getCertificateVerifier());
        service.setTspSource(getUsedTSPSourceAtExtensionTime());
        return service;
    }

    @Override
    protected TSPSource getUsedTSPSourceAtExtensionTime() {
        return getKeyStoreTSPSourceByNameAndTime(SELF_SIGNED_LONG_TSA, extensionTime);
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.XAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return finalSignatureLevel;
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

    @Override
    public void extendAndVerify() throws Exception {
        // do nothing
    }

}

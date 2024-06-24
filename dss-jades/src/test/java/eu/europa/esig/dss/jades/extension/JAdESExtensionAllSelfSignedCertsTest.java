package eu.europa.esig.dss.jades.extension;

import eu.europa.esig.dss.alert.ExceptionOnStatusAlert;
import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESExtensionAllSelfSignedCertsTest extends AbstractJAdESTestExtension {

    private SignatureLevel originalSignatureLevel;
    private SignatureLevel finalSignatureLevel;

    private DSSDocument documentToSign;
    private JAdESService service;
    private CertificateVerifier certificateVerifier;

    @BeforeEach
    public void init() {
        documentToSign = new FileDocument("src/test/resources/sample.json");

        certificateVerifier = getCompleteCertificateVerifier();
        service = new JAdESService(certificateVerifier);
        service.setTspSource(getSelfSignedTsa());
    }

    @Test
    public void bToTTest() throws Exception {
        originalSignatureLevel = SignatureLevel.JAdES_BASELINE_B;
        DSSDocument signedDocument = getSignedDocument(documentToSign);

        finalSignatureLevel = SignatureLevel.JAdES_BASELINE_T;
        DSSDocument extendedDocument = extendSignature(signedDocument);
        assertNotNull(extendedDocument);
        Reports reports = verify(extendedDocument);
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());
    }

    @Test
    public void bToLTTest() throws Exception {
        originalSignatureLevel = SignatureLevel.JAdES_BASELINE_B;
        DSSDocument signedDocument = getSignedDocument(documentToSign);

        certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

        finalSignatureLevel = SignatureLevel.JAdES_BASELINE_LT;
        Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Error on signature augmentation to LT-level."));
        assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

        certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

        DSSDocument extendedDocument = extendSignature(signedDocument);
        assertNotNull(extendedDocument);
        Reports reports = verify(extendedDocument);
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());
    }

    @Test
    public void tToLTTest() throws Exception {
        originalSignatureLevel = SignatureLevel.JAdES_BASELINE_T;
        DSSDocument signedDocument = getSignedDocument(documentToSign);

        certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

        finalSignatureLevel = SignatureLevel.JAdES_BASELINE_LT;
        Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Error on signature augmentation to LT-level."));
        assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

        certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

        DSSDocument extendedDocument = extendSignature(signedDocument);
        assertNotNull(extendedDocument);
        Reports reports = verify(extendedDocument);
        assertEquals(1, reports.getDiagnosticData().getTimestampList().size());
    }

    @Test
    public void bToLTATest() throws Exception {
        originalSignatureLevel = SignatureLevel.JAdES_BASELINE_B;
        DSSDocument signedDocument = getSignedDocument(documentToSign);

        certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

        finalSignatureLevel = SignatureLevel.JAdES_BASELINE_LTA;
        Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Error on signature augmentation to LT-level."));
        assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

        certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

        DSSDocument extendedDocument = extendSignature(signedDocument);
        assertNotNull(extendedDocument);
        Reports reports = verify(extendedDocument);
        assertEquals(2, reports.getDiagnosticData().getTimestampList().size());
    }

    @Test
    public void tToLTATest() throws Exception {
        originalSignatureLevel = SignatureLevel.JAdES_BASELINE_T;
        DSSDocument signedDocument = getSignedDocument(documentToSign);

        certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new ExceptionOnStatusAlert());

        finalSignatureLevel = SignatureLevel.JAdES_BASELINE_LTA;
        Exception exception = assertThrows(AlertException.class, () -> extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Error on signature augmentation to LT-level."));
        assertTrue(exception.getMessage().contains("The signature contains only self-signed certificate chains."));

        certificateVerifier.setAugmentationAlertOnSelfSignedCertificateChains(new SilentOnStatusAlert());

        DSSDocument extendedDocument = extendSignature(signedDocument);
        assertNotNull(extendedDocument);
        Reports reports = verify(extendedDocument);
        assertEquals(2, reports.getDiagnosticData().getTimestampList().size());
    }

    @Override
    protected JAdESService getSignatureServiceToSign() {
        return service;
    }

    @Override
    protected JAdESService getSignatureServiceToExtend() {
        return service;
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return originalSignatureLevel;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return finalSignatureLevel;
    }

    @Override
    protected String getSigningAlias() {
        return SELF_SIGNED_USER;
    }

    @Override
    public void extendAndVerify() throws Exception {
        // do nothing
    }

}

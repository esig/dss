package eu.europa.esig.dss.jades.extension;

import eu.europa.esig.dss.alert.SilentOnStatusAlert;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.validation.CertificateVerifier;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESExtensionBToLTWithRevokedCertTest extends AbstractJAdESTestExtension {

    private JAdESSignatureParameters signatureParameters;
    private JAdESSignatureParameters extensionParameters;

    @BeforeEach
    public void init() {
        signatureParameters = super.getSignatureParameters();
        signatureParameters.setCheckCertificateRevocation(false);

        extensionParameters = super.getExtensionParameters();
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.JAdES_BASELINE_LT;
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected JAdESSignatureParameters getExtensionParameters() {
        return extensionParameters;
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        extensionParameters.setCheckCertificateRevocation(true);
        Exception exception = assertThrows(AlertException.class, () -> super.extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Revoked/Suspended certificate(s) detected."));

        CertificateVerifier completeCertificateVerifier = getCompleteCertificateVerifier();
        completeCertificateVerifier.setAlertOnRevokedCertificate(new SilentOnStatusAlert());
        JAdESService JAdESService = new JAdESService(completeCertificateVerifier);
        JAdESService.setTspSource(getUsedTSPSourceAtExtensionTime());
        return JAdESService.extendDocument(signedDocument, getExtensionParameters());
    }

    @Override
    protected String getSigningAlias() {
        return REVOKED_USER;
    }

}

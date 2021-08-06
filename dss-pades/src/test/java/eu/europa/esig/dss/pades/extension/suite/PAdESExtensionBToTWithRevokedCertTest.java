package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESExtensionBToTWithRevokedCertTest extends AbstractPAdESTestExtension {

    private PAdESSignatureParameters signatureParameters;
    private PAdESSignatureParameters extensionParameters;

    @BeforeEach
    public void init() {
        signatureParameters = super.getSignatureParameters();
        signatureParameters.setCheckCertificateRevocation(false);

        extensionParameters = super.getExtensionParameters();
    }

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.PAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.PAdES_BASELINE_T;
    }

    @Override
    protected PAdESSignatureParameters getSignatureParameters() {
        return signatureParameters;
    }

    @Override
    protected PAdESSignatureParameters getExtensionParameters() {
        return extensionParameters;
    }

    @Override
    protected DSSDocument extendSignature(DSSDocument signedDocument) throws Exception {
        extensionParameters.setCheckCertificateRevocation(true);
        Exception exception = assertThrows(AlertException.class, () -> super.extendSignature(signedDocument));
        assertTrue(exception.getMessage().contains("Revoked/Suspended certificate(s) detected."));

        extensionParameters.setCheckCertificateRevocation(false);
        return super.extendSignature(signedDocument);
    }

    @Override
    protected String getSigningAlias() {
        return REVOKED_USER;
    }

}

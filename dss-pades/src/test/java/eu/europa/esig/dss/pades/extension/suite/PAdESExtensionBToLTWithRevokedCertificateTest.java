package eu.europa.esig.dss.pades.extension.suite;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class PAdESExtensionBToLTWithRevokedCertificateTest extends AbstractPAdESTestExtension {

    @Override
    protected SignatureLevel getOriginalSignatureLevel() {
        return SignatureLevel.PAdES_BASELINE_B;
    }

    @Override
    protected SignatureLevel getFinalSignatureLevel() {
        return SignatureLevel.PAdES_BASELINE_LT;
    }

    @Override
    @Test
    public void extendAndVerify() throws Exception {
        Exception exception = assertThrows(AlertException.class, () -> super.extendAndVerify());
        assertTrue(exception.getMessage().contains("Revoked/Suspended certificate(s) detected."));
    }

    @Override
    protected String getSigningAlias() {
        return REVOKED_USER;
    }

}

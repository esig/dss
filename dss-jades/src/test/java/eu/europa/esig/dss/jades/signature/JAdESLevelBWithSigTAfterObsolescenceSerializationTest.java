package eu.europa.esig.dss.jades.signature;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.spi.DSSUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;

import java.util.Calendar;
import java.util.Date;

public class JAdESLevelBWithSigTAfterObsolescenceSerializationTest extends JAdESLevelBWithSigTSerializationTest {

    private Date signingTime;

    @BeforeEach
    public void initTime() {
        signingTime = DSSUtils.getUtcDate(2025, Calendar.MAY, 15);
    }

    @Override
    protected JAdESSignatureParameters getSignatureParameters() {
        JAdESSignatureParameters signatureParameters = super.getSignatureParameters();
        signatureParameters.bLevel().setSigningDate(signingTime);
        return signatureParameters;
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // iat header shall be present for JAdES-BASELINE-B signature produced starting at 2025-05-15T00:00:00Z (cardinality == 1)!
        Assertions.assertEquals(SignatureLevel.JSON_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

}

package eu.europa.esig.dss.jades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class JAdESLevelTBrokenSigTstTest extends AbstractJAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/jades-flattened-BpT-broken-sigTst.json");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.JAdES_BASELINE_T, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(1, timestampList.size());

        TimestampWrapper timestampWrapper = timestampList.get(0);
        assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestampWrapper.getType());
        assertTrue(timestampWrapper.isMessageImprintDataFound());
        assertFalse(timestampWrapper.isMessageImprintDataIntact());
        assertTrue(timestampWrapper.isSignatureIntact());
        assertTrue(timestampWrapper.isSignatureValid()); // TODO : change the behaviour to false
    }

}

package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESWithCounterSigCopiedSigTestTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/xades-counter-sig-copied-sigtst.xml");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // skip
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        checkNoDuplicateTimestamps(diagnosticData.getTimestampList());

        Set<SignatureWrapper> allCounterSignatures = diagnosticData.getAllCounterSignatures();
        assertEquals(2, allCounterSignatures.size());

        boolean validTstFound = false;
        boolean invalidTstFound = false;
        for (SignatureWrapper signatureWrapper : allCounterSignatures) {
            List<TimestampWrapper> timestampList = signatureWrapper.getTimestampList();
            assertEquals(1, timestampList.size());

            TimestampWrapper timestampWrapper = timestampList.get(0);
            assertEquals(TimestampType.SIGNATURE_TIMESTAMP, timestampWrapper.getType());
            if (timestampWrapper.isMessageImprintDataIntact()) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());
                validTstFound = true;
            } else {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertFalse(timestampWrapper.isSignatureValid());
                invalidTstFound = true;
            }
        }
        assertTrue(validTstFound);
        assertTrue(invalidTstFound);
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // skip
    }

}
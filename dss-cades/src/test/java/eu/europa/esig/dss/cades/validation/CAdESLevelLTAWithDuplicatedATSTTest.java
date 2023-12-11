package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CAdESLevelLTAWithDuplicatedATSTTest extends AbstractCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/cades-lta-duplicated-atst.p7m");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);

        assertEquals(SignatureLevel.CAdES_BASELINE_LTA, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(3, timestampList.size());

        int sigTstCounter = 0;
        int arcTstCounter = 0;
        for (TimestampWrapper timestampWrapper : timestampList) {
            if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());
                ++sigTstCounter;
            } else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());
                ++arcTstCounter;
            }
        }
        assertEquals(1, sigTstCounter);
        assertEquals(2, arcTstCounter);

        assertEquals(timestampList.get(1).getDigestAlgoAndValue().getDigestMethod(),
                timestampList.get(2).getDigestAlgoAndValue().getDigestMethod());
        assertArrayEquals(timestampList.get(1).getDigestAlgoAndValue().getDigestValue(),
                timestampList.get(2).getDigestAlgoAndValue().getDigestValue());
    }

}

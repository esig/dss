package eu.europa.esig.dss.pades.validation.suite;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class DSS2821Test extends AbstractPAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(getClass().getResourceAsStream("/validation/DSS-2821.pdf"));
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        super.checkSignatureLevel(diagnosticData);

        assertEquals(SignatureLevel.PAdES_BASELINE_B, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertEquals(0, signature.getDocumentTimestamps().size());
        assertEquals(0, signature.getTLevelTimestamps().size());
        assertEquals(0, signature.getALevelTimestamps().size());

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(1, timestampList.size());

        TimestampWrapper timestampWrapper = timestampList.get(0);
        assertEquals(TimestampType.DOCUMENT_TIMESTAMP, timestampWrapper.getType());
        assertFalse(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedSignatures()));
        assertFalse(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedCertificates()));
        assertFalse(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedRevocations()));
        assertFalse(Utils.isCollectionNotEmpty(timestampWrapper.getTimestampedTimestamps()));
        assertEquals(1, timestampWrapper.getTimestampedSignedData().size());
    }

}

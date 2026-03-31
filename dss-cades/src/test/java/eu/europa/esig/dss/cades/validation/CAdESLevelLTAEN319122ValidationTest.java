package eu.europa.esig.dss.cades.validation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ArchiveTimestampHashIndexVersion;
import eu.europa.esig.dss.enumerations.ArchiveTimestampType;
import eu.europa.esig.dss.enumerations.TimestampType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

class CAdESLevelLTAEN319122ValidationTest extends AbstractCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(CAdESLevelLTAEN319122ValidationTest.class.getResourceAsStream("/validation/cades-lta-en319122.cms"));
    }

    @Override
    protected void checkTimestamps(final DiagnosticData diagnosticData) {
        super.checkTimestamps(diagnosticData);

        List<TimestampWrapper> timestampList = diagnosticData.getTimestampList();
        assertEquals(2, timestampList.size());

        boolean sigTstFound = false;
        boolean arcTstFound = false;
        for (TimestampWrapper timestampWrapper : timestampList) {
            if (TimestampType.SIGNATURE_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());
                sigTstFound = true;
            } else if (TimestampType.ARCHIVE_TIMESTAMP.equals(timestampWrapper.getType())) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());

                assertEquals(ArchiveTimestampType.CAdES_V3, timestampWrapper.getArchiveTimestampType());
                assertEquals(ArchiveTimestampHashIndexVersion.ATS_HASH_INDEX_V3, timestampWrapper.getAtsHashIndexVersion());

                assertEquals(1, timestampWrapper.getTimestampedSignedData().size());
                assertEquals(1, timestampWrapper.getTimestampedSignatures().size());
                assertEquals(3, timestampWrapper.getTimestampedCertificates().size());
                assertEquals(1, timestampWrapper.getTimestampedRevocations().size());
                assertEquals(1, timestampWrapper.getTimestampedTimestamps().size());
                arcTstFound = true;
            }
        }

        assertTrue(sigTstFound);
        assertTrue(arcTstFound);
    }

}

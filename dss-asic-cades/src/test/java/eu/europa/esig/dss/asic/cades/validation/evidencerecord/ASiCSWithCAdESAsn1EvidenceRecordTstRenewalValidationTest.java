package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithAsn1EvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCSWithCAdESAsn1EvidenceRecordTstRenewalValidationTest extends AbstractASiCWithAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-tst-renewal.asics");
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertTrue(Utils.isCollectionNotEmpty(detachedEvidenceRecords));

        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        assertEquals(2, referenceValidationList.size());

        boolean foundArchiveObject = false;
        boolean notFoundArchiveObject = false;
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == referenceValidation.getType()) {
                assertNotNull(referenceValidation.getDocumentName());
                assertTrue(referenceValidation.isFound());
                assertTrue(referenceValidation.isIntact());
                foundArchiveObject = true;
            } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == referenceValidation.getType()) {
                assertNull(referenceValidation.getDocumentName());
                assertFalse(referenceValidation.isFound());
                assertFalse(referenceValidation.isIntact());
                notFoundArchiveObject = true;
            }
        }
        assertTrue(foundArchiveObject);
        assertTrue(notFoundArchiveObject);

        List<TimestampedReference> timestampedReferences = evidenceRecord.getTimestampedReferences();
        assertTrue(Utils.isCollectionNotEmpty(timestampedReferences));

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        assertEquals(2, Utils.collectionSize(timestamps));

        TimestampToken originalTst = timestamps.get(0);
        assertTrue(originalTst.isProcessed());
        assertTrue(originalTst.isMessageImprintDataFound());
        assertTrue(originalTst.isMessageImprintDataIntact());
        assertEquals(0, Utils.collectionSize(originalTst.getReferenceValidations()));

        TimestampToken tstRenewal = timestamps.get(1);
        assertTrue(tstRenewal.isProcessed());
        assertTrue(tstRenewal.isMessageImprintDataFound());
        assertTrue(tstRenewal.isMessageImprintDataIntact());

        boolean arcTstRefFound = false;
        boolean orphanRefFound = false;
        assertEquals(2, Utils.collectionSize(tstRenewal.getReferenceValidations()));
        for (ReferenceValidation referenceValidation : tstRenewal.getReferenceValidations()) {
            if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP == referenceValidation.getType()) {
                assertNull(referenceValidation.getDocumentName());
                assertTrue(referenceValidation.isFound());
                assertTrue(referenceValidation.isIntact());
                arcTstRefFound = true;
            } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == referenceValidation.getType()) {
                assertNull(referenceValidation.getDocumentName());
                assertFalse(referenceValidation.isFound());
                assertFalse(referenceValidation.isIntact());
                orphanRefFound = true;
            }
        }
        assertTrue(arcTstRefFound);
        assertTrue(orphanRefFound);
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertNotNull(diagnosticData.getContainerInfo());
        assertNotNull(diagnosticData.getContainerType());
        assertNull(diagnosticData.getMimetypeFileContent());
        assertTrue(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getContentFiles()));
        assertFalse(Utils.isCollectionNotEmpty(diagnosticData.getContainerInfo().getManifestFiles()));
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

    @Override
    protected boolean tstCoversOnlyCurrentHashTreeData() {
        return false;
    }

}

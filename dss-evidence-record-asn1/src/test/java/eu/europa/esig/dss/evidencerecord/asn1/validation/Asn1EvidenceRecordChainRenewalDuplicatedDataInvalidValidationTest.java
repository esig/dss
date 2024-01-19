package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class Asn1EvidenceRecordChainRenewalDuplicatedDataInvalidValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-asn1-chain-renewal-duplicated-data-invalid.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument("\t".getBytes()));
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertEquals(1, Utils.collectionSize(detachedEvidenceRecords));

        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        assertEquals(5, referenceValidationList.size());

        int foundRefsCounter = 0;
        int notFoundRefsCounter = 0;
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == referenceValidation.getType()) {
                assertTrue(referenceValidation.isFound());
                assertTrue(referenceValidation.isIntact());
                ++foundRefsCounter;
            } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == referenceValidation.getType()) {
                assertFalse(referenceValidation.isFound());
                assertFalse(referenceValidation.isIntact());
                ++notFoundRefsCounter;
            }
        }
        assertEquals(2, foundRefsCounter);
        assertEquals(3, notFoundRefsCounter);

        List<TimestampedReference> timestampedReferences = evidenceRecord.getTimestampedReferences();
        assertTrue(Utils.isCollectionNotEmpty(timestampedReferences));

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        assertEquals(2, Utils.collectionSize(timestamps));

        boolean validTstFound = false;
        boolean invalidTstFound = false;

        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            assertTrue(timestampToken.isMessageImprintDataFound());
            assertTrue(timestampToken.isMessageImprintDataIntact());

            List<ReferenceValidation> referenceValidations = timestampToken.getReferenceValidations();
            if (Utils.isCollectionEmpty(referenceValidations)) {
                validTstFound = true;
            } else {
                assertEquals(5, Utils.collectionSize(referenceValidations));
                for (ReferenceValidation refValidation : referenceValidations) {
                    assertEquals(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE, refValidation.getType());
                    assertFalse(refValidation.isFound());
                    assertFalse(refValidation.isIntact());
                }
                invalidTstFound = true;
            }
        }

        assertTrue(validTstFound);
        assertTrue(invalidTstFound);
    }

}

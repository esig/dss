package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecordValidator;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XMLEvidenceRecordValidatorTest {

    @Test
    public void simpleERTest() {
        DSSDocument document = new FileDocument("src/test/resources/ER_01.xml");
        DSSDocument detachedDoc = new DigestDocument(DigestAlgorithm.SHA256, "qC9i7yNq1pZCzScV+ya3oBVRR9Y92gnDdYWTCQ8nstU=");

        EvidenceRecordValidator validator = EvidenceRecordValidator.fromDocument(document);
        assertNotNull(validator);

        validator.setDetachedContents(Arrays.asList(detachedDoc));

        EvidenceRecord evidenceRecord = validator.getEvidenceRecord();
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            assertTrue(referenceValidation.isFound());
            assertTrue(referenceValidation.isIntact());
        }

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            assertTrue(timestampToken.isMessageImprintDataFound());
            assertTrue(timestampToken.isMessageImprintDataIntact());
        }
    }

    @Test
    public void invalidERTest() {
        DSSDocument document = new FileDocument("src/test/resources/xmler_1.txt.xml");
        DSSDocument detachedDoc = new DigestDocument(DigestAlgorithm.SHA256, "Y0sCextp4SQtQNU+MSs7SsdxD1W+gfKJtUlEbvZ3i+4=");

        EvidenceRecordValidator validator = EvidenceRecordValidator.fromDocument(document);
        assertNotNull(validator);

        validator.setDetachedContents(Arrays.asList(detachedDoc));

        EvidenceRecord evidenceRecord = validator.getEvidenceRecord();
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            assertTrue(referenceValidation.isFound());
            assertTrue(referenceValidation.isIntact());
        }

        int validTstCounter = 0;
        int invalidTstCounter = 0;
        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            if (timestampToken.isMessageImprintDataFound()) {
                assertTrue(timestampToken.isMessageImprintDataIntact());
                ++validTstCounter;
            } else {
                assertFalse(timestampToken.isMessageImprintDataIntact());
                ++invalidTstCounter;
            };
        }
        assertEquals(1, validTstCounter);
        assertEquals(2, invalidTstCounter);
    }

    @Test
    public void sameDocDigestTest() {
        DSSDocument document = new FileDocument("src/test/resources/er-ao-c2e7c2e2-10ef-4497-bced-82ced6ce93a4.xml");

        List<DSSDocument> detachedDocs = new ArrayList<>();
        detachedDocs.add(new DigestDocument(DigestAlgorithm.SHA512, "NhX4DJ0pPtdAJof5SyLVjlKbjMeRb4+sf933+9WvTPd309eVp6AKFr9+fz+5Vh7puq5IDan+ehh2nnGIawPzFQ=="));

        EvidenceRecordValidator validator = EvidenceRecordValidator.fromDocument(document);
        assertNotNull(validator);

        validator.setDetachedContents(detachedDocs);

        EvidenceRecord evidenceRecord = validator.getEvidenceRecord();
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            assertTrue(referenceValidation.isFound());
            assertTrue(referenceValidation.isIntact());
        }

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            assertTrue(timestampToken.isMessageImprintDataFound());
            assertTrue(timestampToken.isMessageImprintDataIntact());
        }
    }

    @Test
    public void tstRenewalTest() {
        DSSDocument document = new FileDocument("src/test/resources/evidence-record-renewal-test.xml");
        DSSDocument detachedDoc = new DigestDocument(DigestAlgorithm.SHA512, "t/eDuu2Cl/DbkXRiGE/08I5pwtXl95qUJgD5cl9Yzh8pwYE5v4CwbA//K900c4RS7PQMSIwip+PYDN9vnBwNRw==");

        EvidenceRecordValidator validator = EvidenceRecordValidator.fromDocument(document);
        assertNotNull(validator);

        validator.setDetachedContents(Arrays.asList(detachedDoc));

        EvidenceRecord evidenceRecord = validator.getEvidenceRecord();
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            assertTrue(referenceValidation.isFound());
            assertTrue(referenceValidation.isIntact());
        }

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            assertTrue(timestampToken.isMessageImprintDataFound());
            assertTrue(timestampToken.isMessageImprintDataIntact());
        }
    }

    @Test
    public void multipleGroupItemsTest() {
        DSSDocument document = new FileDocument("src/test/resources/er-group-item-42a89ce5-0983-4246-ad7b-a735504cf23c.xml");

        List<DSSDocument> detachedDocs = new ArrayList<>();
        detachedDocs.add(new DigestDocument(DigestAlgorithm.SHA512, "NhX4DJ0pPtdAJof5SyLVjlKbjMeRb4+sf933+9WvTPd309eVp6AKFr9+fz+5Vh7puq5IDan+ehh2nnGIawPzFQ=="));
        detachedDocs.add(new DigestDocument(DigestAlgorithm.SHA512, "NhX4DJ0pPtdAJof5SyLVjlKbjMeRb4+sf933+9WvTPd309eVp6AKFr9+fz+5Vh7puq5IDan+ehh2nnGIawPzFQ=="));
        detachedDocs.add(new DigestDocument(DigestAlgorithm.SHA512, "NhX4DJ0pPtdAJof5SyLVjlKbjMeRb4+sf933+9WvTPd309eVp6AKFr9+fz+5Vh7puq5IDan+ehh2nnGIawPzFQ=="));

        EvidenceRecordValidator validator = EvidenceRecordValidator.fromDocument(document);
        assertNotNull(validator);

        validator.setDetachedContents(detachedDocs);

        EvidenceRecord evidenceRecord = validator.getEvidenceRecord();
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            assertTrue(referenceValidation.isFound());
            assertTrue(referenceValidation.isIntact());
        }

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            assertTrue(timestampToken.isMessageImprintDataFound());
            assertTrue(timestampToken.isMessageImprintDataIntact());
        }
    }

    @Test
    public void perfectTreeTest() {
        DSSDocument document = new FileDocument("src/test/resources/evidence-record-perfectTree_01.xml");

        List<DSSDocument> detachedDocs = new ArrayList<>();
        detachedDocs.add(new DigestDocument(DigestAlgorithm.SHA512, "d6BJBxVejc24ABnmqz38Zoq85Bcf2twnb/kVM8dz51uHLLZEgEkGvtdcy5oDf5MTVSkAR+ryjiPMw3R+/mg2hg=="));

        EvidenceRecordValidator validator = EvidenceRecordValidator.fromDocument(document);
        assertNotNull(validator);

        validator.setDetachedContents(detachedDocs);

        EvidenceRecord evidenceRecord = validator.getEvidenceRecord();
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            assertTrue(referenceValidation.isFound());
            assertTrue(referenceValidation.isIntact());
        }

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            assertTrue(timestampToken.isMessageImprintDataFound());
            assertTrue(timestampToken.isMessageImprintDataIntact());
        }
    }

    @Test
    public void notPerfectTreeTest() {
        DSSDocument document = new FileDocument("src/test/resources/evidence-record-notPerfectTree_01.xml");

        List<DSSDocument> detachedDocs = new ArrayList<>();
        detachedDocs.add(new DigestDocument(DigestAlgorithm.SHA512, "rZ+Vr390XICOXivb252JTm1p86XzihaSKYi2YpB48oQweb9PYzuWJiM2ijr0y+qdTfV2PLMQvILXsNWnw+h13w=="));

        EvidenceRecordValidator validator = EvidenceRecordValidator.fromDocument(document);
        assertNotNull(validator);

        validator.setDetachedContents(detachedDocs);

        EvidenceRecord evidenceRecord = validator.getEvidenceRecord();
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            assertTrue(referenceValidation.isFound());
            assertTrue(referenceValidation.isIntact());
        }

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            assertTrue(timestampToken.isMessageImprintDataFound());
            assertTrue(timestampToken.isMessageImprintDataIntact());
        }
    }

    @Test
    public void ersWithBTest() {
        DSSDocument document = new FileDocument("src/test/resources/evidence-record-notPerfectTree_01.xml");

        List<DSSDocument> detachedDocs = new ArrayList<>();
        detachedDocs.add(new DigestDocument(DigestAlgorithm.SHA512, "rZ+Vr390XICOXivb252JTm1p86XzihaSKYi2YpB48oQweb9PYzuWJiM2ijr0y+qdTfV2PLMQvILXsNWnw+h13w=="));

        EvidenceRecordValidator validator = EvidenceRecordValidator.fromDocument(document);
        assertNotNull(validator);

        validator.setDetachedContents(detachedDocs);

        EvidenceRecord evidenceRecord = validator.getEvidenceRecord();
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            assertTrue(referenceValidation.isFound());
            assertTrue(referenceValidation.isIntact());
        }

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            assertTrue(timestampToken.isMessageImprintDataFound());
            assertTrue(timestampToken.isMessageImprintDataIntact());
        }
    }

    @Test
    public void chainRenewalTest() {
        DSSDocument document = new FileDocument("src/test/resources/evidence-record-chain-renewal.xml");

        List<DSSDocument> detachedDocs = new ArrayList<>();
        detachedDocs.add(new FileDocument("src/test/resources/371e4226-d580-401d-845b-7429c4afcf4c"));

        EvidenceRecordValidator validator = EvidenceRecordValidator.fromDocument(document);
        assertNotNull(validator);

        validator.setDetachedContents(detachedDocs);

        EvidenceRecord evidenceRecord = validator.getEvidenceRecord();
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            assertTrue(referenceValidation.isFound());
            assertTrue(referenceValidation.isIntact());
        }

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            assertTrue(timestampToken.isMessageImprintDataFound());
            assertTrue(timestampToken.isMessageImprintDataIntact());
        }
    }

    @Test
    public void chainRenewalInvalidTest() {
        DSSDocument document = new FileDocument("src/test/resources/evidence-record-chain-renewal-invalid.xml");

        DigestDocument digestDocument = new DigestDocument();
        digestDocument.addDigest(DigestAlgorithm.SHA256, "sq/z8fJz0dy6uDA8Xuc4ycGpY6wdD5YcYF8FRlvixAI=");
        digestDocument.addDigest(DigestAlgorithm.SHA512, "F3lElKvRVhSsXfS8P+YPEXkoK+hS9f0CPF9U/9wJ4Q7T4/UHOOmYF/PKS/0AuJkl1QL7Imw5Q983WAtFd7cTrg==");

        EvidenceRecordValidator validator = EvidenceRecordValidator.fromDocument(document);
        assertNotNull(validator);

        validator.setDetachedContents(Collections.singletonList(digestDocument));

        EvidenceRecord evidenceRecord = validator.getEvidenceRecord();
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            assertTrue(referenceValidation.isFound());
            assertTrue(referenceValidation.isIntact());
        }

        int validTstCounter = 0;
        int invalidTstCounter = 0;
        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            if (timestampToken.isMessageImprintDataFound()) {
                assertTrue(timestampToken.isMessageImprintDataIntact());
                ++validTstCounter;
            } else {
                assertFalse(timestampToken.isMessageImprintDataIntact());
                ++invalidTstCounter;
            };
        }
        assertEquals(1, validTstCounter);
        assertEquals(1, invalidTstCounter);
    }

}

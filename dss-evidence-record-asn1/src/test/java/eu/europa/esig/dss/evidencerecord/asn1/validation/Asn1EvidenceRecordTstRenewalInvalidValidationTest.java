package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class Asn1EvidenceRecordTstRenewalInvalidValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-asn1-tst-renewal-invalid.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Arrays.asList(
                new DigestDocument(DigestAlgorithm.SHA256, "nOLX01D5QYQHQ58MoR3MEquffNsV+ezF7Kk1SCYCuHI=", "doc1"),
                new DigestDocument(DigestAlgorithm.SHA256, "7sxNM1LA6WX9iHle39GmDFrAmzwRAMBS67auC9NDKyY=", "doc2")
        );
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);

        List<ReferenceValidation> referenceValidations = evidenceRecord.getReferenceValidation();
        assertEquals(2, referenceValidations.size());
        for (ReferenceValidation referenceValidation : referenceValidations) {
            assertEquals(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT, referenceValidation.getType());
            assertNotNull(referenceValidation.getName());
            assertTrue(referenceValidation.isFound());
            assertTrue(referenceValidation.isIntact());
        }

        boolean validTstFound = false;
        boolean invalidTstFound = false;
        assertEquals(2, Utils.collectionSize(evidenceRecord.getTimestamps()));
        for (TimestampToken timestampToken : evidenceRecord.getTimestamps()) {
            List<ReferenceValidation> refValidations = timestampToken.getReferenceValidations();
            if (timestampToken.isMessageImprintDataIntact()) {
                assertEquals(0, Utils.collectionSize(refValidations));
                validTstFound = true;
            } else {
                assertEquals(4, Utils.collectionSize(refValidations));
                for (ReferenceValidation referenceValidation : refValidations) {
                    assertEquals(DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE, referenceValidation.getType());
                    assertNull(referenceValidation.getName());
                    assertFalse(referenceValidation.isFound());
                    assertFalse(referenceValidation.isIntact());
                }
                invalidTstFound = true;
            }
        }
        assertTrue(validTstFound);
        assertTrue(invalidTstFound);
    }

    @Override
    protected void checkTimestamps(DiagnosticData diagnosticData) {
        boolean validTstFound = false;
        boolean invalidTstFound = false;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            if (timestampWrapper.isMessageImprintDataIntact()) {
                List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
                assertEquals(1, digestMatchers.size());
                assertEquals(DigestMatcherType.MESSAGE_IMPRINT, digestMatchers.get(0).getType());
                assertTrue(digestMatchers.get(0).isDataFound());
                assertTrue(digestMatchers.get(0).isDataIntact());

                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());
                validTstFound = true;

            } else {
                List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
                assertEquals(5, digestMatchers.size());
                int messageImprintCounter = 0;
                int archiveDataObjectCounter = 0;
                for (XmlDigestMatcher digestMatcher : digestMatchers) {
                    if (DigestMatcherType.MESSAGE_IMPRINT.equals(digestMatcher.getType())) {
                        assertTrue(digestMatcher.isDataFound());
                        assertFalse(digestMatcher.isDataIntact());
                        ++messageImprintCounter;

                    } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE.equals(digestMatcher.getType())) {
                        assertFalse(digestMatcher.isDataFound());
                        assertFalse(digestMatcher.isDataIntact());
                        ++archiveDataObjectCounter;
                    }
                }
                assertEquals(1, messageImprintCounter);
                assertEquals(4, archiveDataObjectCounter);
                invalidTstFound = true;
            }
        }
        assertTrue(validTstFound);
        assertTrue(invalidTstFound);
    }

    @Override
    protected void checkTimestamp(DiagnosticData diagnosticData, TimestampWrapper timestampWrapper) {
        // skip
    }

}

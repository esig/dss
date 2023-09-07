package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.asic.common.validation.AbstractASiCEWithEvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.spi.x509.tsp.TimestampedReference;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithEvidenceRecordDataNotFoundTest extends AbstractASiCEWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/er-multi-file-data-not-found.asice");
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertEquals(1, Utils.collectionSize(detachedEvidenceRecords));
        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);

        int validRefsCounter = 0;
        int invalidRefsCounter = 0;
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        assertEquals(2, Utils.collectionSize(referenceValidationList));
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            if (referenceValidation.isIntact()) {
                assertTrue(referenceValidation.isFound());
                ++validRefsCounter;
            } else {
                assertFalse(referenceValidation.isFound());
                ++invalidRefsCounter;
            }
        }
        assertEquals(1, validRefsCounter);
        assertEquals(1, invalidRefsCounter);

        List<TimestampedReference> timestampedReferences = evidenceRecord.getTimestampedReferences();
        assertTrue(Utils.isCollectionNotEmpty(timestampedReferences));

        int tstCounter = 0;

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            assertTrue(timestampToken.isMessageImprintDataFound());
            assertTrue(timestampToken.isMessageImprintDataIntact());

            if (tstCounter > 0) {
                List<ReferenceValidation> tstReferenceValidationList = timestampToken.getReferenceValidations();
                assertTrue(Utils.isCollectionNotEmpty(tstReferenceValidationList));

                boolean archiveTstDigestFound = false;
                boolean archiveTstSequenceDigestFound = false;
                for (ReferenceValidation referenceValidation : tstReferenceValidationList) {
                    if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP.equals(referenceValidation.getType())) {
                        archiveTstDigestFound = true;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE.equals(referenceValidation.getType())) {
                        archiveTstSequenceDigestFound = true;
                    }
                    assertTrue(referenceValidation.isFound());
                    assertTrue(referenceValidation.isIntact());
                }

                if (tstReferenceValidationList.size() == 1) {
                    assertTrue(archiveTstDigestFound);
                } else {
                    assertTrue(archiveTstSequenceDigestFound);
                }

            }

            ++tstCounter;
        }
    }


    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecords().get(0);

        int validRefsCounter = 0;
        int invalidRefsCounter = 0;
        List<XmlDigestMatcher> digestMatcherList = evidenceRecord.getDigestMatchers();
        assertEquals(2, Utils.collectionSize(digestMatcherList));
        for (XmlDigestMatcher digestMatcher : digestMatcherList) {
            if (digestMatcher.isDataIntact()) {
                assertTrue(digestMatcher.isDataFound());
                ++validRefsCounter;
            } else {
                assertFalse(digestMatcher.isDataFound());
                ++invalidRefsCounter;
            }
        }
        assertEquals(1, validRefsCounter);
        assertEquals(1, invalidRefsCounter);
    }

    protected void verifySimpleReport(SimpleReport simpleReport) {
        assertNotNull(simpleReport);

        for (String erId : simpleReport.getEvidenceRecordIdList()) {
            XmlEvidenceRecord xmlEvidenceRecord = simpleReport.getEvidenceRecordById(erId);
            assertNotNull(simpleReport.getEvidenceRecordPOE(erId));
            assertEquals(Indication.INDETERMINATE, simpleReport.getIndication(erId));
            assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, simpleReport.getSubIndication(erId));

            List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> evidenceRecordScopes = xmlEvidenceRecord.getEvidenceRecordScope();
            assertEquals(1, Utils.collectionSize(evidenceRecordScopes));

            XmlTimestamps timestamps = xmlEvidenceRecord.getTimestamps();
            assertNotNull(timestamps);
            assertTrue(Utils.isCollectionNotEmpty(timestamps.getTimestamp()));

            for (XmlTimestamp xmlTimestamp : timestamps.getTimestamp()) {
                assertNotEquals(Indication.FAILED, xmlTimestamp.getIndication());

                List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> timestampScopes = xmlTimestamp.getTimestampScope();
                assertEquals(1, Utils.collectionSize(timestampScopes));
            }
        }

        assertNotNull(simpleReport.getValidationTime());
    }

}

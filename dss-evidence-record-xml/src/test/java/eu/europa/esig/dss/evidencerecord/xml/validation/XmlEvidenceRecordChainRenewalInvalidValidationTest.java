package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.spi.x509.tsp.TimestampToken;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.validation.evidencerecord.EvidenceRecord;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XmlEvidenceRecordChainRenewalInvalidValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-chain-renewal-invalid.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        DigestDocument digestDocument = new DigestDocument();
        digestDocument.setName("Detached document");
        digestDocument.addDigest(DigestAlgorithm.SHA256, "sq/z8fJz0dy6uDA8Xuc4ycGpY6wdD5YcYF8FRlvixAI=");
        digestDocument.addDigest(DigestAlgorithm.SHA512, "F3lElKvRVhSsXfS8P+YPEXkoK+hS9f0CPF9U/9wJ4Q7T4/UHOOmYF/PKS/0AuJkl1QL7Imw5Q983WAtFd7cTrg==");
        return Collections.singletonList(digestDocument);
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertEquals(1, detachedEvidenceRecords.size());

        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        assertEquals(1, referenceValidationList.size());

        ReferenceValidation referenceValidation = referenceValidationList.get(0);
        assertEquals(DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT, referenceValidation.getType());
        assertTrue(referenceValidation.isFound());
        assertTrue(referenceValidation.isIntact());

        int passedTstCounter = 0;
        int failedTstCounter = 0;

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        assertEquals(2, timestamps.size());

        for (TimestampToken timestampToken : timestamps) {
            assertTrue(timestampToken.isProcessed());
            assertTrue(timestampToken.isMessageImprintDataFound());
            assertTrue(timestampToken.isMessageImprintDataIntact());

            List<ReferenceValidation> tstReferenceValidationList = timestampToken.getReferenceValidations();
            if (Utils.isCollectionNotEmpty(tstReferenceValidationList)) {
                assertEquals(2, tstReferenceValidationList.size());

                boolean archiveDataObjectRefFound = false;
                boolean archiveTstSequenceRefFound = false;
                for (ReferenceValidation tstReferenceValidation : tstReferenceValidationList) {
                    if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == tstReferenceValidation.getType()) {
                        assertTrue(tstReferenceValidation.isFound());
                        assertTrue(tstReferenceValidation.isIntact());
                        archiveDataObjectRefFound = true;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE == tstReferenceValidation.getType()) {
                        assertTrue(tstReferenceValidation.isFound());
                        assertFalse(tstReferenceValidation.isIntact());
                        archiveTstSequenceRefFound = true;
                    }
                }
                assertTrue(archiveDataObjectRefFound);
                assertTrue(archiveTstSequenceRefFound);
                ++failedTstCounter;

            } else {
                ++passedTstCounter;
            }
        }

        assertEquals(1, passedTstCounter);
        assertEquals(1, failedTstCounter);
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        EvidenceRecordWrapper evidenceRecordWrapper = evidenceRecords.get(0);
        List<XmlSignatureScope> evidenceRecordScopes = evidenceRecordWrapper.getEvidenceRecordScopes();
        assertEquals(1, evidenceRecordScopes.size());

        assertEquals(2, diagnosticData.getTimestampList().size());

        boolean initialTstFound = false;
        boolean chainRenewalTstFound = false;
        for (TimestampWrapper timestampWrapper : diagnosticData.getTimestampList()) {
            assertTrue(timestampWrapper.isMessageImprintDataFound());
            assertTrue(timestampWrapper.isMessageImprintDataIntact());
            assertTrue(timestampWrapper.isSignatureIntact());

            List<XmlDigestMatcher> digestMatchers = timestampWrapper.getDigestMatchers();
            if (digestMatchers.size() == 1) {
                assertEquals(DigestMatcherType.MESSAGE_IMPRINT, digestMatchers.get(0).getType());
                assertTrue(timestampWrapper.isSignatureValid());
                initialTstFound = true;

            } else if (digestMatchers.size() == 3) {
                assertFalse(timestampWrapper.isSignatureValid());

                boolean messageImprintFound = false;
                boolean archiveDataObjectFound = false;
                boolean previousChainFound = false;
                for (XmlDigestMatcher digestMatcher : digestMatchers) {
                    if (DigestMatcherType.MESSAGE_IMPRINT == digestMatcher.getType()) {
                        assertTrue(digestMatcher.isDataFound());
                        assertTrue(digestMatcher.isDataIntact());
                        messageImprintFound = true;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == digestMatcher.getType()) {
                        assertTrue(digestMatcher.isDataFound());
                        assertTrue(digestMatcher.isDataIntact());
                        archiveDataObjectFound = true;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP_SEQUENCE == digestMatcher.getType()) {
                        assertTrue(digestMatcher.isDataFound());
                        assertFalse(digestMatcher.isDataIntact());
                        previousChainFound = true;
                    }
                }
                assertTrue(messageImprintFound);
                assertTrue(archiveDataObjectFound);
                assertTrue(previousChainFound);

                List<XmlSignatureScope> timestampScopes = timestampWrapper.getTimestampScopes();
                assertEquals(1, timestampScopes.size());
                assertEquals(evidenceRecordScopes.get(0).getSignerData(), timestampScopes.get(0).getSignerData());

                chainRenewalTstFound = true;
            }
        }
        assertTrue(initialTstFound);
        assertTrue(chainRenewalTstFound);
    }

}

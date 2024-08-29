package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithAsn1EvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlSignatureScope;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTimestampType;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.ReferenceValidation;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
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

class ASiCEWithCAdESAsn1EvidenceRecordFullRenewalNoManifestValidationTest extends AbstractASiCWithAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-full-renewal-no-manifest.asice");
    }

    @Override
    protected void checkDetachedEvidenceRecords(List<EvidenceRecord> detachedEvidenceRecords) {
        assertTrue(Utils.isCollectionNotEmpty(detachedEvidenceRecords));

        EvidenceRecord evidenceRecord = detachedEvidenceRecords.get(0);
        List<ReferenceValidation> referenceValidationList = evidenceRecord.getReferenceValidation();
        assertEquals(2, referenceValidationList.size());

        int foundArchiveObjectCounter = 0;
        int notFoundArchiveObjectCounter = 0;
        for (ReferenceValidation referenceValidation : referenceValidationList) {
            if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == referenceValidation.getType()) {
                assertNotNull(referenceValidation.getDocumentName());
                assertTrue(referenceValidation.isFound());
                assertTrue(referenceValidation.isIntact());
                ++foundArchiveObjectCounter;
            } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == referenceValidation.getType()) {
                assertNull(referenceValidation.getDocumentName());
                assertFalse(referenceValidation.isFound());
                assertFalse(referenceValidation.isIntact());
                ++notFoundArchiveObjectCounter;
            }
        }
        assertEquals(0, foundArchiveObjectCounter);
        assertEquals(2, notFoundArchiveObjectCounter);

        List<TimestampedReference> timestampedReferences = evidenceRecord.getTimestampedReferences();
        assertFalse(Utils.isCollectionNotEmpty(timestampedReferences));

        List<TimestampToken> timestamps = evidenceRecord.getTimestamps();
        assertEquals(3, Utils.collectionSize(timestamps));

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

        TimestampToken chainRenewalTst = timestamps.get(2);
        assertTrue(tstRenewal.isProcessed());
        assertTrue(tstRenewal.isMessageImprintDataFound());
        assertTrue(tstRenewal.isMessageImprintDataIntact());

        assertEquals(1, Utils.collectionSize(chainRenewalTst.getReferenceValidations()));
        assertNull(chainRenewalTst.getReferenceValidations().get(0).getDocumentName());
        assertFalse(chainRenewalTst.getReferenceValidations().get(0).isFound());
        assertFalse(chainRenewalTst.getReferenceValidations().get(0).isIntact());
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecords().get(0);
        boolean arcTstFound = false;
        boolean tstRenewalFound = false;
        boolean tstChainRenewalFound = false;
        List<TimestampWrapper> timestamps = evidenceRecord.getTimestampList();
        for (TimestampWrapper timestamp : timestamps) {
            assertTrue(timestamp.isMessageImprintDataFound());
            assertTrue(timestamp.isMessageImprintDataIntact());
            assertTrue(timestamp.isSignatureIntact());
            assertTrue(timestamp.isSignatureValid());

            if (EvidenceRecordTimestampType.ARCHIVE_TIMESTAMP == timestamp.getEvidenceRecordTimestampType()) {
                arcTstFound = true;

            } else if (EvidenceRecordTimestampType.TIMESTAMP_RENEWAL_ARCHIVE_TIMESTAMP == timestamp.getEvidenceRecordTimestampType()) {
                int messageImprintCounter = 0;
                int foundRefCounter = 0;
                int orphanRefCounter = 0;
                int arcTstRefCounter = 0;
                for (XmlDigestMatcher xmlDigestMatcher : timestamp.getDigestMatchers()) {
                    if (DigestMatcherType.MESSAGE_IMPRINT == xmlDigestMatcher.getType()) {
                        assertTrue(xmlDigestMatcher.isDataFound());
                        assertTrue(xmlDigestMatcher.isDataIntact());
                        ++messageImprintCounter;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == xmlDigestMatcher.getType()) {
                        ++foundRefCounter;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == xmlDigestMatcher.getType()) {
                        assertFalse(xmlDigestMatcher.isDataFound());
                        assertFalse(xmlDigestMatcher.isDataIntact());
                        ++orphanRefCounter;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP == xmlDigestMatcher.getType()) {
                        assertTrue(xmlDigestMatcher.isDataFound());
                        assertTrue(xmlDigestMatcher.isDataIntact());
                        ++arcTstRefCounter;
                    }
                }
                assertEquals(1, messageImprintCounter);
                assertEquals(0, foundRefCounter);
                assertEquals(1, orphanRefCounter);
                assertEquals(1, arcTstRefCounter);
                tstRenewalFound = true;

            } else if (EvidenceRecordTimestampType.HASH_TREE_RENEWAL_ARCHIVE_TIMESTAMP == timestamp.getEvidenceRecordTimestampType()) {
                int messageImprintCounter = 0;
                int foundRefCounter = 0;
                int orphanRefCounter = 0;
                int arcTstRefCounter = 0;
                for (XmlDigestMatcher xmlDigestMatcher : timestamp.getDigestMatchers()) {
                    if (DigestMatcherType.MESSAGE_IMPRINT == xmlDigestMatcher.getType()) {
                        assertTrue(xmlDigestMatcher.isDataFound());
                        assertTrue(xmlDigestMatcher.isDataIntact());
                        ++messageImprintCounter;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == xmlDigestMatcher.getType()) {
                        ++foundRefCounter;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == xmlDigestMatcher.getType()) {
                        assertFalse(xmlDigestMatcher.isDataFound());
                        assertFalse(xmlDigestMatcher.isDataIntact());
                        ++orphanRefCounter;
                    } else if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_TIME_STAMP == xmlDigestMatcher.getType()) {
                        ++arcTstRefCounter;
                    }
                }
                assertEquals(1, messageImprintCounter);
                assertEquals(0, foundRefCounter);
                assertEquals(1, orphanRefCounter);
                assertEquals(0, arcTstRefCounter);
                tstChainRenewalFound = true;
            }

            List<XmlSignatureScope> timestampScopes = timestamp.getTimestampScopes();
            assertFalse(Utils.isCollectionNotEmpty(timestampScopes));

            List<XmlTimestampedObject> timestampedObjects = timestamp.getTimestampedObjects();
            assertTrue(Utils.isCollectionNotEmpty(timestampedObjects));
        }
        assertTrue(arcTstFound);
        assertTrue(tstRenewalFound);
        assertTrue(tstChainRenewalFound);
    }

    @Override
    protected void checkEvidenceRecordScopes(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecords().get(0);
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getEvidenceRecordScopes()));
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        EvidenceRecordWrapper evidenceRecord = diagnosticData.getEvidenceRecords().get(0);
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredObjects()));
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
    protected void verifySimpleReport(SimpleReport simpleReport) {
        XmlEvidenceRecord evidenceRecord = simpleReport.getEvidenceRecordById(simpleReport.getFirstEvidenceRecordId());
        assertNotNull(evidenceRecord);
        assertEquals(Indication.INDETERMINATE, evidenceRecord.getIndication());
        assertEquals(SubIndication.SIGNED_DATA_NOT_FOUND, evidenceRecord.getSubIndication());
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

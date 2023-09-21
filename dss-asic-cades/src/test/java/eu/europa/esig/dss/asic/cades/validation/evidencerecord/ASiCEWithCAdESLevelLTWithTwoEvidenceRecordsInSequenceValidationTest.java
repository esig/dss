package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlContainerInfo;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.diagnostic.jaxb.XmlTimestampedObject;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureScopeType;
import eu.europa.esig.dss.enumerations.TimestampedObjectType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamps;
import eu.europa.esig.dss.utils.Utils;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class ASiCEWithCAdESLevelLTWithTwoEvidenceRecordsInSequenceValidationTest extends AbstractASiCEWithCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/cades-lt-with-two-ers-sequence-multi-files.sce");
    }

    @Override
    protected void checkEvidenceRecordTimestampedReferences(DiagnosticData diagnosticData) {
        super.checkEvidenceRecordTimestampedReferences(diagnosticData);

        XmlContainerInfo containerInfo = diagnosticData.getContainerInfo();

        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(2, evidenceRecords.size());

        boolean firstErFound = false;
        boolean secondErFound = false;
        for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
            XmlManifestFile erManifest = null;
            for (XmlManifestFile xmlManifestFile : containerInfo.getManifestFiles()) {
                if (xmlManifestFile.getSignatureFilename().equals(evidenceRecord.getFilename())) {
                    erManifest = xmlManifestFile;
                }
            }
            assertNotNull(erManifest);

            boolean coversSignature = false;
            boolean coversSignedData = false;
            boolean coversCertificates = false;
            boolean coversRevocationData = false;
            boolean coversTimestamps = false;
            boolean coversEvidenceRecords = false;
            List<XmlTimestampedObject> coveredObjects = evidenceRecord.getCoveredObjects();
            assertTrue(Utils.isCollectionNotEmpty(coveredObjects));
            for (XmlTimestampedObject reference : coveredObjects) {
                if (TimestampedObjectType.SIGNATURE == reference.getCategory()) {
                    coversSignature = true;
                } else if (TimestampedObjectType.SIGNED_DATA == reference.getCategory()) {
                    coversSignedData = true;
                } else if (TimestampedObjectType.CERTIFICATE == reference.getCategory()) {
                    coversCertificates = true;
                } else if (TimestampedObjectType.REVOCATION == reference.getCategory()) {
                    coversRevocationData = true;
                } else if (TimestampedObjectType.TIMESTAMP == reference.getCategory()) {
                    coversTimestamps = true;
                } else if (TimestampedObjectType.EVIDENCE_RECORD == reference.getCategory()) {
                    coversEvidenceRecords = true;
                }
            }
            assertTrue(coversSignature);
            assertTrue(coversSignedData);
            assertTrue(coversCertificates);
            assertTrue(coversTimestamps);
            assertTrue(coversRevocationData);
            if (coversEvidenceRecords) {
                assertEquals(6, coveredObjects.stream()
                        .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).count());
                secondErFound = true;
            } else {
                assertEquals(4, coveredObjects.stream()
                        .filter(r -> TimestampedObjectType.SIGNED_DATA == r.getCategory()).count());
                firstErFound = true;
            }
        }
        assertTrue(firstErFound);
        assertTrue(secondErFound);
    }

    protected void verifySimpleReport(SimpleReport simpleReport) {
        Set<String> evidenceRecordIds = new HashSet<>();
        for (String sigId : simpleReport.getSignatureIdList()) {
            List<XmlEvidenceRecord> signatureEvidenceRecords = simpleReport.getSignatureEvidenceRecords(sigId);
            assertEquals(1, signatureEvidenceRecords.size());

            XmlEvidenceRecord xmlEvidenceRecord = signatureEvidenceRecords.get(0);
            evidenceRecordIds.add(xmlEvidenceRecord.getId());
            assertNotNull(xmlEvidenceRecord.getPOETime());
            assertNotEquals(Indication.FAILED, xmlEvidenceRecord.getIndication());

            List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> evidenceRecordScopes = xmlEvidenceRecord.getEvidenceRecordScope();
            assertEquals(4, evidenceRecordScopes.size());

            boolean sigFileFound = false;
            for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope evidenceRecordScope : evidenceRecordScopes) {
                assertEquals(SignatureScopeType.FULL, evidenceRecordScope.getScope());
                if (simpleReport.getTokenFilename(sigId).equals(evidenceRecordScope.getName())) {
                    sigFileFound = true;
                }
            }
            assertTrue(sigFileFound);

            XmlTimestamps timestamps = xmlEvidenceRecord.getTimestamps();
            assertNotNull(timestamps);
            assertTrue(Utils.isCollectionNotEmpty(timestamps.getTimestamp()));

            for (XmlTimestamp xmlTimestamp : timestamps.getTimestamp()) {
                assertNotEquals(Indication.FAILED, xmlTimestamp.getIndication());

                List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> timestampScopes = xmlTimestamp.getTimestampScope();
                assertEquals(Utils.collectionSize(evidenceRecordScopes), Utils.collectionSize(timestampScopes));

                sigFileFound = false;
                for (eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope tstScope : timestampScopes) {
                    assertEquals(SignatureScopeType.FULL, tstScope.getScope());
                    if (simpleReport.getTokenFilename(sigId).equals(tstScope.getName())) {
                        sigFileFound = true;
                    }
                }
                assertTrue(sigFileFound);
            }
        }

        List<String> detachedEvidenceRecordIdList = simpleReport.getEvidenceRecordIdList();
        assertEquals(1, detachedEvidenceRecordIdList.size());
        assertFalse(evidenceRecordIds.contains(detachedEvidenceRecordIdList.get(0)));

        XmlEvidenceRecord xmlEvidenceRecord = simpleReport.getEvidenceRecordById(detachedEvidenceRecordIdList.get(0));

        evidenceRecordIds.add(xmlEvidenceRecord.getId());
        assertNotNull(xmlEvidenceRecord.getPOETime());
        assertNotEquals(Indication.FAILED, xmlEvidenceRecord.getIndication());

        List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> evidenceRecordScopes = xmlEvidenceRecord.getEvidenceRecordScope();
        assertEquals(2, evidenceRecordScopes.size());

        XmlTimestamps timestamps = xmlEvidenceRecord.getTimestamps();
        assertNotNull(timestamps);
        assertTrue(Utils.isCollectionNotEmpty(timestamps.getTimestamp()));

        for (XmlTimestamp xmlTimestamp : timestamps.getTimestamp()) {
            assertNotEquals(Indication.FAILED, xmlTimestamp.getIndication());

            List<eu.europa.esig.dss.simplereport.jaxb.XmlSignatureScope> timestampScopes = xmlTimestamp.getTimestampScope();
            assertEquals(Utils.collectionSize(evidenceRecordScopes), Utils.collectionSize(timestampScopes));
        }
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 0; // not used
    }

}

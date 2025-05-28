package eu.europa.esig.dss.asic.cades.preservation.container;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.diagnostic.jaxb.XmlDigestMatcher;
import eu.europa.esig.dss.diagnostic.jaxb.XmlManifestFile;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.DigestMatcherType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlEvidenceRecord;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithCAdESEROnlyAddContainerXMLEvidenceRecordTest extends AbstractASiCWithCAdESTestAddContainerEvidenceRecord {

    @Override
    protected List<DSSDocument> getDocumentsToPreserve() {
        return Collections.singletonList(new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-one-file.asice"));
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-er-asn1-one-file-asice.xml");
    }

    @Override
    protected ASiCContainerType getASiCContainerType() {
        return ASiCContainerType.ASiC_E;
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD;
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 3;
    }

    @Override
    protected void checkEvidenceRecordDigestMatchers(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();

        int xmlERCounter = 0;
        int asn1ERCounter = 0;
        for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
            int dataObjectDM = 0;
            int orphanObjectDM = 0;
            for (XmlDigestMatcher xmlDigestMatcher : evidenceRecord.getDigestMatchers()) {
                if (DigestMatcherType.EVIDENCE_RECORD_ARCHIVE_OBJECT == xmlDigestMatcher.getType()) {
                    assertTrue(xmlDigestMatcher.isDataFound());
                    assertTrue(xmlDigestMatcher.isDataIntact());
                    ++dataObjectDM;
                } else if (DigestMatcherType.EVIDENCE_RECORD_ORPHAN_REFERENCE == xmlDigestMatcher.getType()) {
                    assertFalse(xmlDigestMatcher.isDataFound());
                    assertFalse(xmlDigestMatcher.isDataIntact());
                    ++orphanObjectDM;
                }
            }

            if (EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD == evidenceRecord.getEvidenceRecordType()) {
                assertEquals(3, dataObjectDM);
                assertEquals(0, orphanObjectDM);
                ++xmlERCounter;

            } else if (EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD == evidenceRecord.getEvidenceRecordType()) {
                assertEquals(1, dataObjectDM);
                assertEquals(1, orphanObjectDM);
                ++asn1ERCounter;
            }
        }
        assertEquals(1, xmlERCounter);
        assertEquals(1, asn1ERCounter);
    }

    @Override
    protected void checkEvidenceRecordCoverage(DiagnosticData diagnosticData, SignatureWrapper signature) {
        List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
        assertEquals(1, evidenceRecords.size());

        evidenceRecords = diagnosticData.getEvidenceRecords();
        assertEquals(2, evidenceRecords.size());

        int xmlERCounter = 0;
        int asn1ERCounter = 0;
        for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
            if (EvidenceRecordTypeEnum.XML_EVIDENCE_RECORD == evidenceRecord.getEvidenceRecordType()) {
                if (evidenceRecord.getFilename().equals("META-INF/evidencerecord001.xml")) {
                    assertEquals(3, Utils.collectionSize(evidenceRecord.getEvidenceRecordScopes()));
                    assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignedData()));
                    assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignatures()));
                    assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredTimestamps()));
                    assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredCertificates()));
                    assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredEvidenceRecords()));
                    ++xmlERCounter;

                } else if (evidenceRecord.getFilename().equals("META-INF/evidencerecord.ers")) {
                    assertEquals(1, Utils.collectionSize(evidenceRecord.getEvidenceRecordScopes()));
                    assertTrue(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignedData()));
                    assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredSignatures()));
                    assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredTimestamps()));
                    assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredCertificates()));
                    assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredRevocations()));
                    assertFalse(Utils.isCollectionNotEmpty(evidenceRecord.getCoveredEvidenceRecords()));
                    ++asn1ERCounter;
                }

            }
        }
        assertEquals(1, xmlERCounter);
        assertEquals(1, asn1ERCounter);
    }

    @Override
    protected void checkContainerInfo(DiagnosticData diagnosticData) {
        assertEquals(getASiCContainerType(), diagnosticData.getContainerType());
        int xmlERCounter = 0;
        int asn1ERCounter = 0;
        if (ASiCContainerType.ASiC_E == getASiCContainerType()) {
            List<XmlManifestFile> manifestFiles = diagnosticData.getContainerInfo().getManifestFiles();
            assertTrue(Utils.isCollectionNotEmpty(manifestFiles));
            for (XmlManifestFile xmlManifestFile : manifestFiles) {
                if (xmlManifestFile.getSignatureFilename().equals("META-INF/evidencerecord001.xml")) {
                    assertEquals("META-INF/ASiCEvidenceRecordManifest002.xml", xmlManifestFile.getFilename());
                    assertEquals(3, xmlManifestFile.getEntries().size());
                    ++xmlERCounter;
                } else if (xmlManifestFile.getSignatureFilename().equals("META-INF/evidencerecord.ers")) {
                    assertEquals("META-INF/ASiCEvidenceRecordManifest.xml", xmlManifestFile.getFilename());
                    assertEquals(1, xmlManifestFile.getEntries().size());
                    ++asn1ERCounter;
                }
            }
        }
        assertEquals(1, xmlERCounter);
        assertEquals(1, asn1ERCounter);
    }

    @Override
    protected void verifySimpleReport(SimpleReport simpleReport) {
        List<String> evidenceRecordIdList = simpleReport.getEvidenceRecordIdList();
        assertEquals(2, evidenceRecordIdList.size());

        int xmlERCounter = 0;
        int asn1ERCounter = 0;
        for (String erId : evidenceRecordIdList) {
            XmlEvidenceRecord evidenceRecord = simpleReport.getEvidenceRecordById(erId);
            if (evidenceRecord.getFilename().equals("META-INF/evidencerecord001.xml")) {
                assertEquals(3, Utils.collectionSize(evidenceRecord.getEvidenceRecordScope()));
                ++xmlERCounter;
            } else if (evidenceRecord.getFilename().equals("META-INF/evidencerecord.ers")) {
                assertEquals(1, Utils.collectionSize(evidenceRecord.getEvidenceRecordScope()));
                ++asn1ERCounter;
            }
        }
        assertEquals(1, xmlERCounter);
        assertEquals(1, asn1ERCounter);
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // skip
    }

}

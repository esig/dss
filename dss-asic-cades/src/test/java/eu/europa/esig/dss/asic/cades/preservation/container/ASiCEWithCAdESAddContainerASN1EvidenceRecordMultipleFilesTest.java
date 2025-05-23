package eu.europa.esig.dss.asic.cades.preservation.container;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.utils.Utils;
import org.junit.jupiter.api.BeforeAll;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ASiCEWithCAdESAddContainerASN1EvidenceRecordMultipleFilesTest extends AbstractASiCWithCAdESTestAddContainerEvidenceRecord {

    private static List<DSSDocument> originalDocuments;

    @BeforeAll
    public static void init() {
        originalDocuments = Arrays.asList(
                new InMemoryDocument("Test 12345".getBytes()),
                new InMemoryDocument("Test 67890".getBytes())
        );
    }

    @Override
    protected List<DSSDocument> getDocumentsToPreserve() {
        return originalDocuments;
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-sce-multiple-docs.ers");
    }

    @Override
    protected ASiCContainerType getASiCContainerType() {
        return ASiCContainerType.ASiC_E;
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return EvidenceRecordTypeEnum.ASN1_EVIDENCE_RECORD;
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 2;
    }

    @Override
    protected void checkEvidenceRecordTimestamps(DiagnosticData diagnosticData) {
        List<EvidenceRecordWrapper> evidenceRecords = diagnosticData.getEvidenceRecords();
        for (EvidenceRecordWrapper evidenceRecord : evidenceRecords) {
            List<TimestampWrapper> timestamps = evidenceRecord.getTimestampList();
            assertTrue(Utils.isCollectionNotEmpty(timestamps));
            for (TimestampWrapper timestampWrapper : timestamps) {
                assertTrue(timestampWrapper.isMessageImprintDataFound());
                assertTrue(timestampWrapper.isMessageImprintDataIntact());
                assertTrue(timestampWrapper.isSignatureIntact());
                assertTrue(timestampWrapper.isSignatureValid());
            }
        }
    }

}

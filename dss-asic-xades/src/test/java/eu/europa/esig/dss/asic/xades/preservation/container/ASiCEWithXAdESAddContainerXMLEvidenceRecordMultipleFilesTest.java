package eu.europa.esig.dss.asic.xades.preservation.container;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.BeforeAll;

import java.util.Arrays;
import java.util.List;

class ASiCEWithXAdESAddContainerXMLEvidenceRecordMultipleFilesTest extends AbstractASiCWithXAdESAddContainerEvidenceRecordTest {

    private static List<DSSDocument> originalDocuments;

    @BeforeAll
    public static void init() {
        originalDocuments = Arrays.asList(
                new FileDocument("src/test/resources/signable/empty.zip"),
                new FileDocument("src/test/resources/signable/test.txt"),
                new FileDocument("src/test/resources/signable/test.zip")
        );
    }

    @Override
    protected List<DSSDocument> getDocumentsToPreserve() {
        return originalDocuments;
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-sce-multiple-docs.xml");
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

}

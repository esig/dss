package eu.europa.esig.dss.asic.xades.preservation.container;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.EvidenceRecordWrapper;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;

class ASiCEWithXAdESLevelBAddContainerXMLEvidenceRecordDataOnlyTest extends AbstractASiCWithXAdESAddContainerEvidenceRecordTest {

    @Override
    protected List<DSSDocument> getDocumentsToPreserve() {
        return Collections.singletonList(new FileDocument("src/test/resources/signable/asic_xades.zip"));
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-asic_xades.xml");
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
        return 1;
    }


    @Override
    protected void checkEvidenceRecordCoverage(DiagnosticData diagnosticData, SignatureWrapper signature) {
        List<EvidenceRecordWrapper> evidenceRecords = signature.getEvidenceRecords();
        assertFalse(Utils.isCollectionNotEmpty(evidenceRecords)); // not applied to signature
    }

}

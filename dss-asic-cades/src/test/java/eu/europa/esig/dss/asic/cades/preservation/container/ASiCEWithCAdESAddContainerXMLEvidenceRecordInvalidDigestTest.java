package eu.europa.esig.dss.asic.cades.preservation.container;

import eu.europa.esig.dss.enumerations.ASiCContainerType;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCEWithCAdESAddContainerXMLEvidenceRecordInvalidDigestTest extends AbstractASiCWithCAdESTestAddContainerEvidenceRecord {

    @Override
    protected List<DSSDocument> getDocumentsToPreserve() {
        return Collections.singletonList(new FileDocument("src/test/resources/signable/test.txt"));
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-test-txt-invalid.xml");
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
        return 1;
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(IllegalInputException.class, super::addERAndValidate);
        assertEquals("The digest covered by the evidence record do not correspond to " +
                "the digest computed on the provided content!", exception.getMessage());
    }

}

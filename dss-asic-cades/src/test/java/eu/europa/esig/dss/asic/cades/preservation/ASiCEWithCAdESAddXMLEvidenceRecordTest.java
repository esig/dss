package eu.europa.esig.dss.asic.cades.preservation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCEWithCAdESAddXMLEvidenceRecordTest extends AbstractASiCWithCAdESAddEvidenceRecordTest {

    @Override
    protected DSSDocument getSignatureDocument() {
        return new FileDocument("src/test/resources/validation/onefile-ok.asice");
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-onefile-ok.xml");
    }

    @Override
    protected int getNumberOfCoveredDocuments() {
        return 2;
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(IllegalInputException.class, super::addERAndValidate);
        assertEquals("Only RFC 4998 ERS type of Evidence Records is allowed for CAdES signatures! " +
                "Identified type of evidence record: 'XML_EVIDENCE_RECORD'", exception.getMessage());
    }

}

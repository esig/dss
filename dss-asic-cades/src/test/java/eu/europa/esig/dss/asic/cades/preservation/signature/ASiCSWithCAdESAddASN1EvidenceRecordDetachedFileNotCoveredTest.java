package eu.europa.esig.dss.asic.cades.preservation.signature;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ASiCSWithCAdESAddASN1EvidenceRecordDetachedFileNotCoveredTest extends AbstractASiCWithCAdESAddEvidenceRecordTest {

    @Override
    protected DSSDocument getSignatureDocument() {
        return new FileDocument("src/test/resources/validation/onefile-ok.asics");
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/incorporation/evidence-record-onefile-ok-s-detached-file-not-covered.ers");
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(IllegalInputException.class, super::addERAndValidate);
        assertEquals("The digest covered by the evidence record do not correspond to " +
                "the digest computed on the detached content!", exception.getMessage());
    }

}

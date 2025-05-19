package eu.europa.esig.dss.xades.preservation;

import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class XAdESLevelBAddXMLEvidenceRecordInvalidDigestTest extends AbstractXAdESAddEvidenceRecordTest {

    @Override
    protected DSSDocument getSignatureDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/incorporation/X-B-B.xml");
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/incorporation/evidence-record-X-B-LT-270f7c0b892f5ad2a1178a20b68d101a.xml");
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return null;
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(IllegalInputException.class, super::addERAndValidate);
        assertEquals("The digest covered by the evidence record do not correspond to the digest computed on " +
                "the signature and/or detached content! In case of detached signature, " +
                "please use #setDetachedContent method to provide original documents.", exception.getMessage());
    }

}

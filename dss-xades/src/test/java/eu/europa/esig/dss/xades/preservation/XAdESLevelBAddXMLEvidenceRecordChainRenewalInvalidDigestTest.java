package eu.europa.esig.dss.xades.preservation;

import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.EvidenceRecordTypeEnum;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XAdESLevelBAddXMLEvidenceRecordChainRenewalInvalidDigestTest extends AbstractXAdESAddEvidenceRecordTest {

    @Override
    protected DSSDocument getSignatureDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/incorporation/X-B-B.xml");
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new FileDocument("src/test/resources/validation/evidence-record/incorporation/evidence-record-chain-renewal-invalid-digest-X-B-B.xml");
    }

    @Override
    protected EvidenceRecordTypeEnum getEvidenceRecordType() {
        return null;
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(AlertException.class, super::addERAndValidate);
        assertTrue(exception.getMessage().contains("Broken timestamp(s) detected."));
    }

}

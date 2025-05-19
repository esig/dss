package eu.europa.esig.dss.cms.stream.preservation;

import eu.europa.esig.dss.cades.preservation.AbstractCAdESAddEvidenceRecordTest;
import eu.europa.esig.dss.enumerations.EvidenceRecordIncorporationType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CMSStreamAddASN1EvidenceRecordTest extends AbstractCAdESAddEvidenceRecordTest {

    @Override
    protected DSSDocument getSignatureDocument() {
        return new InMemoryDocument(CMSStreamAddASN1EvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/Signature-C-LT-d233a2d9-a257-40dc-bcdb-bf4516b6d1da.p7m"));
    }

    @Override
    protected DSSDocument getEvidenceRecordDocument() {
        return new InMemoryDocument(CMSStreamAddASN1EvidenceRecordTest.class.getResourceAsStream(
                "/validation/evidence-record/evidence-record-d233a2d9-a257-40dc-bcdb-bf4516b6d1da.ers"));
    }

    @Override
    protected EvidenceRecordIncorporationType getEvidenceRecordIncorporationType() {
        return null;
    }

    @Test
    @Override
    public void addERAndValidate() {
        Exception exception = assertThrows(UnsupportedOperationException.class, super::addERAndValidate);
        assertEquals("Embedding of Evidence Record is not supported by the dss-cms-stream implementation! " +
                "Please switch to 'dss-cms-object' if support is required.", exception.getMessage());
    }

}
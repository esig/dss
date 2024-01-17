package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.Arrays;
import java.util.List;

public class Asn1EvidenceRecordChainRenewalValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
    	return new FileDocument("src/test/resources/ER-2Chains3ATS.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
    	return Arrays.asList(new InMemoryDocument("content of data object DO-01".getBytes(), "ER-2Chains3ATS1.bin"),
    						 new InMemoryDocument("content of data object DO-02".getBytes(), "ER-2Chains3ATS2.bin"));
    }

    @Override
    protected boolean tstCoversOnlyCurrentHashTreeData() {
        // second tst covers other data too
        return false;
    }

}

package eu.europa.esig.dss.evidencerecord.asn1.validation;

import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public class Asn1EvidenceRecordChainRenewalValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
    	return new FileDocument("src/test/resources/ER-2Chains3ATS.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
    	return Arrays.asList(new InMemoryDocument("content of data object DO-01".getBytes(), "ER-2Chains3ATS1.bin"),
    						 new InMemoryDocument("content of data object DO-02".getBytes(), "ER-2Chains3ATS2.bin"));
    }

}

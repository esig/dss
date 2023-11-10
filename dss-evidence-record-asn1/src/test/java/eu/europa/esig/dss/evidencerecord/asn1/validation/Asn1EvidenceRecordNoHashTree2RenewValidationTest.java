package eu.europa.esig.dss.evidencerecord.asn1.validation;

import java.util.Collections;
import java.util.List;

import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

public class Asn1EvidenceRecordNoHashTree2RenewValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
    	return new FileDocument("src/test/resources/1_2_Renew_Unsorted.er");
    }

    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument("123456".getBytes()));
    }

}

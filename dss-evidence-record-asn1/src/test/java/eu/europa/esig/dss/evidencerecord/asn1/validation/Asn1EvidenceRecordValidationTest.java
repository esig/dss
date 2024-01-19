package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.Collections;
import java.util.List;

public class Asn1EvidenceRecordValidationTest extends AbstractAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-asn1-simple.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument("1".getBytes()));
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

}

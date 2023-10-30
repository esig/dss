package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.model.InMemoryDocument;

import java.util.Collections;
import java.util.List;

public class XmlEvidenceRecordSimpleValidationValidationTest extends AbstractEvidenceRecordTestValidation {

//    @Override
//    protected DSSDocument getSignedDocument() {
//        return new FileDocument("src/test/resources/er-simple.xml");
//    }
//
//    @Override
//    protected List<DSSDocument> getDetachedContents() {
//        return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, "qC9i7yNq1pZCzScV+ya3oBVRR9Y92gnDdYWTCQ8nstU="));
//    }

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-chain-renewal.xml");
    }
    
    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new InMemoryDocument("da2e47f2-53f4-4610-8210-f0f05d67d0c9".getBytes()));
    }

}

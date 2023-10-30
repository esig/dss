package eu.europa.esig.dss.evidencerecord.xml.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.Collections;
import java.util.List;

public class XmlEvidenceRecordSimpleValidationValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/er-simple.xml");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, "qC9i7yNq1pZCzScV+ya3oBVRR9Y92gnDdYWTCQ8nstU="));
    }

}

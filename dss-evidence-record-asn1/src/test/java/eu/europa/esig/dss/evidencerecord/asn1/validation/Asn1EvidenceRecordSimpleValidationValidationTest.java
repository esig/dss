package eu.europa.esig.dss.evidencerecord.asn1.validation;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.Collections;
import java.util.List;

public class Asn1EvidenceRecordSimpleValidationValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/M3_06_step04_003_0fdaf7a1-401c-4608-ae01-c605ddc1c8b2_0.asn1.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Collections.singletonList(new DigestDocument(DigestAlgorithm.SHA256, "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="));
    }

}

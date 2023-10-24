package eu.europa.esig.dss.evidencerecord.asn1.validation;

import java.util.Arrays;
import java.util.List;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.evidencerecord.common.validation.AbstractEvidenceRecordTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.DigestDocument;
import eu.europa.esig.dss.model.FileDocument;

public class Asn1EvidenceRecordSimpleValidationValidationTest extends AbstractEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
    	return new FileDocument("src/test/resources/BIN-1_ER.ers");
    }

    @Override
    protected List<DSSDocument> getDetachedContents() {
        return Arrays.asList(
                new DigestDocument(DigestAlgorithm.SHA256, "odTntQ2Wk/mjGy6UhOpq36WFg3cw/iupTROl1MgcMt8=", "some binary content"),
                new DigestDocument(DigestAlgorithm.SHA256, "2Eg+KWYIINZGWWKP1rUlW4zrtlKk5Ws2VEVJA6fSSgQ=", "some binary content")
        );
    }

}

package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class ASiCEWithCAdESLevelLTWithEvidenceRecordValidationTest extends AbstractASiCEWithCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/cades-lt-with-er.sce");
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 1; // only signature file is covered
    }

}

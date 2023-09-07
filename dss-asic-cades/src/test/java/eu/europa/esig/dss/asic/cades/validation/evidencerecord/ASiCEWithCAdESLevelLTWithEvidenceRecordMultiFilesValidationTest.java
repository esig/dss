package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class ASiCEWithCAdESLevelLTWithEvidenceRecordMultiFilesValidationTest extends AbstractASiCEWithCAdESWithEvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/cades-lt-with-er-multi-files.sce");
    }

    @Override
    protected int getNumberOfExpectedEvidenceScopes() {
        return 4; // signature file + 3 signed data files covered
    }

}

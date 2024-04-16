package eu.europa.esig.dss.asic.cades.validation.evidencerecord;

import eu.europa.esig.dss.asic.common.validation.AbstractASiCWithAsn1EvidenceRecordTestValidation;
import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

public class ASiCEWithCAdESAsn1EvidenceRecordValidationTest extends AbstractASiCWithAsn1EvidenceRecordTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/evidencerecord/er-asn1-one-file.asice");
    }

    @Override
    protected boolean allArchiveDataObjectsProvidedToValidation() {
        return false;
    }

    @Override
    protected void checkOrphanTokens(DiagnosticData diagnosticData) {
        // skip
    }

}

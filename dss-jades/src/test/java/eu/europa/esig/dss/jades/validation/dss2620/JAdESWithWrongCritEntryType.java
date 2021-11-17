package eu.europa.esig.dss.jades.validation.dss2620;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

public class JAdESWithWrongCritEntryType extends AbstractJAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/dss2620/jades-with-crit-with-wrong-entry-type.json");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.JSON_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isStructuralValidationValid());
        assertEquals(1, signature.getStructuralValidationMessages().size());
        assertEquals("#/crit/0: expected type: String, found: JSONArray", signature.getStructuralValidationMessages().get(0));
    }

}

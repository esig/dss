package eu.europa.esig.dss.jades.validation.dss2620;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JAdESWithExpirationTimeHeaderTest extends AbstractJAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/dss2620/jades-with-expiration-time-header.json");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.JAdES_BASELINE_B, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

}

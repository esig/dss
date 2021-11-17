package eu.europa.esig.dss.jades.validation.dss2620;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.jades.validation.AbstractJAdESTestValidation;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JAdESWithCritAndDuplicatedHeaderTest extends AbstractJAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/dss2620/jades-with-crit-with-duplicated-header.json");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        assertEquals(SignatureLevel.JSON_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

}

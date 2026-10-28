package eu.europa.esig.dss.cbades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CBAdESLevelBCoseSign1WithUnsupportedKeyInCritTest extends AbstractCBAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/cb-ades-with-crit-unsupported-key.cose");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // valid structurally, but not supported 'crit' header value
        assertEquals(SignatureLevel.CBOR_NOT_ETSI, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }
    
}

package eu.europa.esig.dss.cades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class CAdESExtendedAValidationTest extends AbstractCAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/cades-extended-a.pkcs7");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // short A, without C/X/XL
        assertEquals(SignatureLevel.CAdES_A, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        assertNull(diagnosticData.getSignatureDate(diagnosticData.getFirstSignatureId()));
    }

}

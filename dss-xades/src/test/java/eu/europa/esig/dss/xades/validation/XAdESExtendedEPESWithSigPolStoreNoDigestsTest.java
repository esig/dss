package eu.europa.esig.dss.xades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class XAdESExtendedEPESWithSigPolStoreNoDigestsTest extends AbstractXAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/xades-extended-epes-sigPolStore-noDigest.xml");
    }

    @Override
    protected void checkSignatureLevel(DiagnosticData diagnosticData) {
        // no digests within SignaturePolicyId
        assertEquals(SignatureLevel.XAdES_BES, diagnosticData.getSignatureFormat(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkSigningDate(DiagnosticData diagnosticData) {
        assertNull(diagnosticData.getSignatureDate(diagnosticData.getFirstSignatureId()));
    }

    @Override
    protected void checkSignaturePolicyStore(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertTrue(signature.isPolicyStorePresent());
        assertNotNull(signature.getPolicyStoreId());
        assertNull(signature.getPolicyStoreDigestAlgoAndValue());
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(signature.isStructuralValidationValid());

        boolean sigPolIdErrorFound = false;
        for (String error : signature.getStructuralValidationMessages()) {
            if (error.contains("xades:SignaturePolicyId")) {
                sigPolIdErrorFound = true;
            }
        }
        assertTrue(sigPolIdErrorFound);
    }

}

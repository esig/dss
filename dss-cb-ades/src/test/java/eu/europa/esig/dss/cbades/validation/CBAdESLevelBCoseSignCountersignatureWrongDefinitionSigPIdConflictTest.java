package eu.europa.esig.dss.cbades.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.enumerations.COSESignatureType;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CBAdESLevelBCoseSignCountersignatureWrongDefinitionSigPIdConflictTest extends AbstractCBAdESTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/cb-ades-cosesign-countersignature-wrong-definition-sigPId-conflict.cose");
    }

    @Override
    protected void checkNumberOfSignatures(DiagnosticData diagnosticData) {
        super.checkNumberOfSignatures(diagnosticData);
        assertEquals(1, diagnosticData.getSignatures().size());
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        List<SignatureWrapper> signatures = diagnosticData.getSignatures();
        assertEquals(1, signatures.size());

        SignatureWrapper signatureWrapper = signatures.get(0);
        assertEquals(COSESignatureType.COSE_SIGN, signatureWrapper.getCOSESignatureType());

        assertFalse(signatureWrapper.isStructuralValidationValid());
        assertEquals(1, signatureWrapper.getStructuralValidationMessages().size());
        assertTrue(signatureWrapper.getStructuralValidationMessages().get(0).contains("/[1]/268[0]/.cbor/7/1"));
        assertTrue(signatureWrapper.getStructuralValidationMessages().get(0).contains("Expected map but got bstr"));
    }

}

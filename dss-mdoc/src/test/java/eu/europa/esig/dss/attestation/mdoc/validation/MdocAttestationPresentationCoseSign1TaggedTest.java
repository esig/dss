package eu.europa.esig.dss.attestation.mdoc.validation;

import eu.europa.esig.dss.diagnostic.DiagnosticData;
import eu.europa.esig.dss.diagnostic.SignatureWrapper;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.utils.Utils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

class MdocAttestationPresentationCoseSign1TaggedTest extends AbstractMdocAttestationPresentationTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/mdoc-cose-sign1-tagged.cbor");
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Override
    protected void checkStructureValidation(DiagnosticData diagnosticData) {
        SignatureWrapper signature = diagnosticData.getSignatureById(diagnosticData.getFirstSignatureId());
        assertFalse(Utils.isCollectionEmpty(signature.getStructuralValidationMessages()));
        assertEquals("Signature is a tagged COSE_Sign1! Shall be untagged COSE_Sign1.", signature.getStructuralValidationMessages().get(0));
    }

}

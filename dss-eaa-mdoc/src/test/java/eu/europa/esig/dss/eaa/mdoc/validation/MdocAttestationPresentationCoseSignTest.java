package eu.europa.esig.dss.eaa.mdoc.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.FileDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MdocAttestationPresentationCoseSignTest extends AbstractMdocAttestationPresentationTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new FileDocument("src/test/resources/validation/mdoc-cose-sign.cbor");
    }

    @Override
    protected boolean keyBindingPresent() {
        return false;
    }

    @Test
    @Override
    public void validate() {
        Exception exception = assertThrows(IllegalInputException.class, super::validate);
        assertEquals("The mdoc signature shall be represented by a 'COSE_Sign1' object!", exception.getMessage());
    }

}

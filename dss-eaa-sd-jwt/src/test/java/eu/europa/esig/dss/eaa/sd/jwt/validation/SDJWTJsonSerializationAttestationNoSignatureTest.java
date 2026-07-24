package eu.europa.esig.dss.eaa.sd.jwt.validation;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.exception.IllegalInputException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SDJWTJsonSerializationAttestationNoSignatureTest extends AbstractSDJWTTestValidation {

    @Override
    protected DSSDocument getSignedDocument() {
        return new InMemoryDocument(this.getClass().getResourceAsStream("/validation/sdjwt-json-no-signatures.json"));
    }

    @Test
    @Override
    public void validate() {
        Exception exception = assertThrows(IllegalInputException.class, super::validate);
        assertEquals("The provided SD-JWT token does not contain any signature!", exception.getMessage());
    }

}
